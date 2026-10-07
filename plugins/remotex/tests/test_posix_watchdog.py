import os
import json
import signal
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tempfile
import shlex
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import ssh_vnext


@unittest.skipUnless(os.name == 'posix' and shutil.which('setsid'), 'POSIX process groups required')
class PosixWatchdogTests(unittest.TestCase):
    def payload(self, script, timeout):
        return ssh_vnext._shell_payload('sh', script, [],
            {'memoryMb': None, 'cpuSeconds': None, 'maxProcesses': None}, timeout)

    def test_completed_script_closes_capture_before_deadline(self):
        started = time.monotonic()
        result = subprocess.run(['sh', '-s'], input=self.payload('printf done', 4),
                                capture_output=True, timeout=7)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'done')
        self.assertLess(time.monotonic() - started, 2)

    def test_long_script_is_still_terminated(self):
        started = time.monotonic()
        result = subprocess.run(['sh', '-s'], input=self.payload('sleep 20', 1),
                                capture_output=True, timeout=6)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 5)

    def test_term_ignoring_script_gets_kill_escalation(self):
        result = subprocess.run(['sh', '-s'], input=self.payload("trap '' TERM; sleep 20", 1),
                                capture_output=True, timeout=6)
        self.assertNotEqual(result.returncode, 0)

    def test_original_exit_code_is_preserved(self):
        result = subprocess.run(['sh', '-s'], input=self.payload('exit 7', 4),
                                capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 7)

    def test_term_ignoring_descendant_cannot_outlive_script_shell(self):
        try:
            result = subprocess.run(['sh', '-s'],
                input=self.payload("(trap '' TERM; sleep 20) & wait", 1),
                capture_output=True, timeout=5)
        except subprocess.TimeoutExpired as error:
            for line in (error.stderr or b'').decode().splitlines():
                if line.startswith(ssh_vnext.META_PREFIX):
                    pid = json.loads(line[len(ssh_vnext.META_PREFIX):])['remotePid']
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            self.fail('TERM-ignoring descendant kept transport open')
        self.assertNotEqual(result.returncode, 0)

    def test_wrapper_early_exit_cleans_term_ignoring_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = shlex.quote(str(Path(directory) / 'ready'))
            payload = self.payload("trap '' TERM; touch " + marker + '; sleep 20', 4)
            injected = ('while [ ! -f ' + marker + ' ]; do sleep 0.01; done\nexit 7\n').encode()
            payload = payload.replace(b'set +e\nwait "$child_pid"', injected + b'set +e\nwait "$child_pid"')
            try:
                result = subprocess.run(['sh', '-s'], input=payload, capture_output=True, timeout=3)
            except subprocess.TimeoutExpired as error:
                for line in (error.stderr or b'').decode().splitlines():
                    if line.startswith(ssh_vnext.META_PREFIX):
                        pid = json.loads(line[len(ssh_vnext.META_PREFIX):])['remotePid']
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                self.fail('Early wrapper exit left workload alive')
            self.assertEqual(result.returncode, 7)

    def test_broken_metadata_pipe_does_not_leave_workload_running(self):
        payload = self.payload("trap '' TERM; echo CHILD_PID=$$; sleep 20", 4)
        process = subprocess.Popen(['sh', '-s'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stderr.close()
        process.stderr = None
        try:
            process.communicate(payload, timeout=3)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            for line in (error.output or b'').decode().splitlines():
                if line.startswith('CHILD_PID='):
                    try:
                        os.killpg(int(line.split('=')[1]), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            self.fail('Broken metadata pipe left workload alive')
        self.assertNotEqual(process.returncode, 0)
