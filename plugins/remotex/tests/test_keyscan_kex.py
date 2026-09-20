import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import host_keys


class KeyscanKexTests(unittest.TestCase):
    def test_windows_kex_failure_uses_fixed_git_scanner(self):
        failed = {'returncode': 1, 'stdout': '', 'stderr': 'choose_kex: unsupported KEX method sntrup761x25519-sha512@openssh.com'}
        success = {'returncode': 0, 'stdout': '172.15.255.93 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMe9yet+ryzYKBVodBzE99AMvjMr77nkhb0Ik8GPQMcR\n', 'stderr': ''}
        with patch.object(host_keys, '_git_keyscan', return_value='C:/Program Files/Git/usr/bin/ssh-keyscan.exe', create=True), patch.object(host_keys.core, 'find_executable', return_value='inbox-keyscan'), patch.object(host_keys.execution, 'run_process', side_effect=[failed, success]) as run:
            keys, _ = host_keys._scan({'host': '172.15.255.93', 'port': 22}, 5)
        self.assertEqual(keys[0]['fingerprint'], 'SHA256:TJLEl7tjJGt6Re10pciP4FPV98TnrgBeq8b1laAAisI')
        self.assertEqual(run.call_args_list[1].args[0][0], 'C:/Program Files/Git/usr/bin/ssh-keyscan.exe')

    def test_connection_failure_does_not_fallback(self):
        failed = {'returncode': 1, 'stdout': '', 'stderr': 'Connection refused'}
        with patch.object(host_keys.core, 'find_executable', return_value='inbox-keyscan'), patch.object(host_keys.execution, 'run_process', return_value=failed) as run:
            with self.assertRaises(host_keys.core.ToolError):
                host_keys._scan({'host': '172.15.255.93', 'port': 22}, 5)
        self.assertEqual(run.call_count, 1)

    def test_missing_fallback_and_same_executable_fail_closed(self):
        failed = {'returncode': 1, 'stdout': '', 'stderr': 'unsupported KEX method test'}
        for fallback in (None, 'inbox-keyscan'):
            with self.subTest(fallback=fallback), patch.object(host_keys, '_git_keyscan', return_value=fallback), patch.object(host_keys.core, 'find_executable', return_value='inbox-keyscan'), patch.object(host_keys.execution, 'run_process', return_value=failed) as run:
                with self.assertRaises(host_keys.core.ToolError):
                    host_keys._scan({'host': '172.15.255.93', 'port': 22}, 5)
                self.assertEqual(run.call_count, 1)

    def test_failed_or_timed_out_fallback_is_not_accepted(self):
        failed = {'returncode': 1, 'stdout': '', 'stderr': 'unsupported KEX method test'}
        for result in (
            {'returncode': 1, 'stdout': '', 'stderr': 'Connection refused'},
            {'returncode': 0, 'stdout': 'host ssh-ed25519 YWJj\n', 'timed_out': True},
        ):
            with self.subTest(result=result), patch.object(host_keys, '_git_keyscan', return_value='git-keyscan'), patch.object(host_keys.core, 'find_executable', return_value='inbox-keyscan'), patch.object(host_keys.execution, 'run_process', side_effect=[failed, result]) as run:
                with self.assertRaises(host_keys.core.ToolError):
                    host_keys._scan({'host': '172.15.255.93', 'port': 22}, 5)
                self.assertEqual(run.call_count, 2)

    def test_initial_timeout_does_not_start_another_scan(self):
        failed = {'returncode': 1, 'stdout': '', 'stderr': 'unsupported KEX method test', 'timed_out': True}
        with patch.object(host_keys.core, 'find_executable', return_value='inbox-keyscan'), patch.object(host_keys.execution, 'run_process', return_value=failed) as run:
            with self.assertRaises(host_keys.core.ToolError):
                host_keys._scan({'host': '172.15.255.93', 'port': 22}, 5)
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
