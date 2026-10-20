from __future__ import annotations

import copy
import json
import queue
import re
import threading
import uuid
from typing import Any

import remotex_core as core
from web_request_profiles import decode_v3_capture


class Channel:
    """One supervisor-owned pipe; no attach port, bearer token or content files."""

    def __init__(self, process, job, *, profile, requester, resource, deadline, config):
        self.process, self.job = process, job
        self.profile, self.requester, self.resource = profile, requester, resource
        self.deadline, self.config = deadline, copy.deepcopy(config)
        self._lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._responses: queue.Queue = queue.Queue(maxsize=2)
        self._closed = threading.Event()
        self.authorize = None
        self.authorize_network = None
        self.authorize_batch = None
        self.on_startup = None
        self.on_close = None

    def start(self):
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            while not self._closed.is_set():
                line = self.process.stdout.readline(131073)
                if not line or len(line) > 131072 or not line.endswith(b'\n'):
                    break
                value = json.loads(line)
                if isinstance(value,dict) and set(value)=={'event','state'} and value['event']=='startup-state':
                    if not isinstance(value['state'],dict) or not callable(self.on_startup) or self.on_startup(value['state']) is not True:
                        break
                    continue
                if isinstance(value,dict) and set(value)=={'event','checks'} and value['event']=='authorization-check-batch':
                    checks=value['checks']
                    if (len(line)>32768 or not isinstance(checks,list) or not 2<=len(checks)<=16 or any(
                        not isinstance(row,dict) or set(row)!={'id','request'} or
                        not isinstance(row['id'],str) or re.fullmatch(r'[a-f0-9]{32}',row['id']) is None or
                        not isinstance(row['request'],dict) for row in checks) or
                        len({row['id'] for row in checks})!=len(checks)):
                        break
                    results=[False]*len(checks)
                    if callable(self.authorize_batch):
                        try:
                            reply=self.authorize_batch([row['request'] for row in checks])
                            if isinstance(reply,list) and len(reply)==len(checks) and all(type(v) is bool for v in reply):
                                results=reply
                        except Exception:
                            pass
                    self._send({'authorization_batch_reply':[{'authorization_reply':row['id'],'allowed':allowed}
                        for row,allowed in zip(checks,results)]})
                    continue
                if isinstance(value,dict) and set(value)=={'event','id','request'} and value['event']=='authorization-check':
                    if not isinstance(value['id'],str) or re.fullmatch(r'[a-f0-9]{32}',value['id']) is None or not isinstance(value['request'],dict):
                        break
                    request=value['request']
                    v3='version' in request or 'capture' in request
                    if v3:
                        startup=request.get('startup')
                        if (len(line)>32768 or set(request)!={'kind','version','phase','attempt_id','capture','startup'} or
                                request['kind']!='network' or type(request['version']) is not int or request['version']!=3 or
                                request['phase'] not in {'bootstrap','login-once'} or request['attempt_id'] is not None or
                                not isinstance(startup,dict) or set(startup)!={'preauth_lifecycle','resume_id','document_id','generation'} or
                                type(startup['generation']) is not int or not 0<=startup['generation']<=9007199254740991 or
                                any(not isinstance(startup[k],str) or re.fullmatch('[a-f0-9]{32}',startup[k]) is None
                                    for k in ('preauth_lifecycle','resume_id','document_id'))):
                            break
                        decode_v3_capture(request['capture'])
                        if request['capture']['origin']!=self.config.get('origin'):
                            break
                    allowed=False
                    if value['request'].get('kind')=='network' and callable(self.authorize_network):
                        try:
                            reply=self.authorize_network(value['request'],value['id'])
                            if isinstance(reply,dict) and set(reply)=={'allowed','permit'} and reply['allowed'] is True and isinstance(reply['permit'],dict):
                                if v3 and (reply['permit'].get('kind')!='initialization-permit-v3' or reply['permit'].get('version')!=3 or
                                        reply['permit'].get('check_id')!=value['id']):
                                    reply=False
                                else:
                                    self._send({'authorization_reply':value['id'],**reply})
                                    continue
                            allowed=reply is True and not v3
                        except Exception:
                            allowed=False
                        self._send({'authorization_reply':value['id'],'allowed':allowed})
                        continue
                    if callable(self.authorize):
                        try:
                            allowed=self.authorize(value['request']) is True
                        except Exception:
                            allowed=False
                    self._send({'authorization_reply':value['id'],'allowed':allowed})
                    continue
                if not isinstance(value, dict) or set(value) != {'id', 'result'} or not isinstance(value['result'], dict):
                    break
                self._responses.put_nowait(value)
            self.close()
        except (OSError, ValueError, queue.Full, core.ToolError):
            self.close()

    def close(self):
        changed=False
        with self._close_lock:
            if not self._closed.is_set():
                self._closed.set()
                changed=True
                if self.process.poll() is None:
                    self.job.terminate()
                try:
                    self._responses.put_nowait(None)
                except queue.Full:
                    pass
        if changed and callable(self.on_close):
            self.on_close()

    def _send(self, value):
        packet=json.dumps(value,separators=(',',':')).encode()+b'\n'
        if len(packet)>65536:
            raise core.ToolError('Web control command exceeds the bounded protocol')
        with self._write_lock:
            if not self.available:
                raise core.ToolError('Web control channel is closed')
            self.process.stdin.write(packet)
            self.process.stdin.flush()

    def send_control(self, event, generation):
        if event!='revoke' or type(generation) is not int or generation<0:
            raise core.ToolError('Invalid authorization control event')
        self._send({'control_event':event,'generation':generation})

    @property
    def available(self):
        return not self._closed.is_set() and self.process.poll() is None

    def request(self, operation: str, arguments: dict[str, Any], timeout=30):
        with self._lock:
            if not self.available:
                raise core.ToolError('Web control channel is closed; start a new owned session')
            identifier = uuid.uuid4().hex
            try:
                self._send({'id':identifier, 'operation':operation, 'arguments':arguments})
                response = self._responses.get(timeout=timeout)
                if response is None or response.get('id') != identifier:
                    raise ValueError()
            except (OSError, ValueError, queue.Empty):
                # An uncertain action is never replayed. Revoke the whole owned session.
                self.close()
                raise core.ToolError('Web control channel closed after an incomplete command; do not replay the action') from None
            return response['result']
