from __future__ import annotations

import copy
import json
import queue
import threading
import uuid
from typing import Any

import remotex_core as core


class Channel:
    """One supervisor-owned pipe; no attach port, bearer token or content files."""

    def __init__(self, process, job, *, profile, requester, resource, deadline, config):
        self.process, self.job = process, job
        self.profile, self.requester, self.resource = profile, requester, resource
        self.deadline, self.config = deadline, copy.deepcopy(config)
        self._lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._responses: queue.Queue = queue.Queue(maxsize=2)
        self._closed = threading.Event()

    def start(self):
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            while not self._closed.is_set():
                line = self.process.stdout.readline(131073)
                if not line or len(line) > 131072 or not line.endswith(b'\n'):
                    break
                value = json.loads(line)
                if not isinstance(value, dict) or set(value) != {'id', 'result'} or not isinstance(value['result'], dict):
                    break
                self._responses.put_nowait(value)
            self.close()
        except (OSError, ValueError, queue.Full):
            self.close()

    def close(self):
        with self._close_lock:
            if not self._closed.is_set():
                self._closed.set()
                if self.process.poll() is None:
                    self.job.terminate()
                try:
                    self._responses.put_nowait(None)
                except queue.Full:
                    pass

    @property
    def available(self):
        return not self._closed.is_set() and self.process.poll() is None

    def request(self, operation: str, arguments: dict[str, Any], timeout=30):
        with self._lock:
            if not self.available:
                raise core.ToolError('Web control channel is closed; start a new owned session')
            identifier = uuid.uuid4().hex
            packet = json.dumps({'id':identifier, 'operation':operation, 'arguments':arguments}).encode() + b'\n'
            if len(packet) > 4096:
                raise core.ToolError('Web control command exceeds the bounded protocol')
            try:
                self.process.stdin.write(packet)
                self.process.stdin.flush()
                response = self._responses.get(timeout=timeout)
                if response is None or response.get('id') != identifier:
                    raise ValueError()
            except (OSError, ValueError, queue.Empty):
                # An uncertain action is never replayed. Revoke the whole owned session.
                self.close()
                raise core.ToolError('Web control channel closed after an incomplete command; do not replay the action') from None
            return response['result']
