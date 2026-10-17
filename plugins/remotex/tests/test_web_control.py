from __future__ import annotations

import io
import json
import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import audit_log
import remotex_core as core
import web_adapter
import profile_config


class WebControlTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.path=self.root/'config.json'
        self.path.write_text(json.dumps({'version':2,'credentials':{},'profiles':{},'defaults':{}}))
        patch=mock.patch.dict(os.environ,{'REMOTEX_CONFIG':str(self.path),'REMOTEX_WEB_STATE_DIR':str(self.root/'web'),
            'REMOTEX_VM_QUEUE_FILE':str(self.root/'queue.json'),'REMOTEX_VM_QUEUE_LEASE_FILE':str(self.root/'leases.json')})
        patch.start();self.addCleanup(patch.stop)

    def prepared(self):
        return profile_config.prepare({'profile':'web-lab','kind':'web','url':'https://console.example:6868/#/',
            'account':'operator','credential_ref':'web-operator','credential_source':'windows-credential-manager',
            'username_selector':'#user','password_selector':'#pass','submit_selector':'#login','confirm':False})

    def channel(self):
        p = self.prepared()
        self.path.write_text(json.dumps(p.candidate))
        import queue_leases
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':600})
        channel = mock.Mock(profile='web-lab', requester='owner', resource=p.profile['queue_resource'],
                            deadline=int((time.time()+120)*1000), config=p.profile)
        channel.request.return_value={'ok':True,'authenticationVerified':True,'text':'private-content'}
        self.patch = mock.patch.dict(web_adapter._CHANNELS, {'a'*32:channel}, clear=True)
        self.patch.start();self.addCleanup(self.patch.stop)
        return channel

    def test_new_tools_do_not_accept_credentials_scripts_urls_or_raw_http(self):
        for name in ('remotex_web_observe','remotex_web_navigate','remotex_web_read_result'):
            spec = web_adapter.TOOLS[name]
            self.assertFalse(set(spec['inputSchema']['properties']) & {'password','url','script','javascript','headers','body','cookies','selector'})

    def test_control_requires_original_owner_and_current_covering_lease(self):
        channel=self.channel()
        with self.assertRaises(core.ToolError):
            web_adapter.observe({'session_id':'a'*32,'requester':'other'})
        channel.request.assert_not_called()
        channel.close.assert_not_called()
        import queue_leases
        queue_leases.queue_renew({'profile':'web-lab','requester':'owner','lease_seconds':60})
        with self.assertRaises(core.ToolError):
            web_adapter.observe({'session_id':'a'*32,'requester':'owner'})
        channel.request.assert_not_called()
        channel.close.assert_called_once()

    def test_control_refuses_configuration_rotation_and_foreign_mcp_process(self):
        channel=self.channel()
        with self.assertRaises(core.ToolError):
            web_adapter.observe({'session_id':'b'*32,'requester':'owner'})
        data=json.loads(self.path.read_text());data['profiles']['web-lab']['certificate_sha256']='ab'*32
        self.path.write_text(json.dumps(data))
        with self.assertRaises(core.ToolError):
            web_adapter.observe({'session_id':'a'*32,'requester':'owner'})
        channel.request.assert_not_called()
        channel.close.assert_called_once()

    def test_observation_is_not_persisted_in_audit(self):
        channel=self.channel()
        result=web_adapter.observe({'session_id':'a'*32,'requester':'owner'})
        self.assertIn('private-content',result['content'][0]['text'])
        self.assertNotIn('private-content',json.dumps(audit_log.summarize_result(result)))
        channel.request.assert_called_once()

    def test_control_rejects_unknown_fields_before_sending(self):
        channel=self.channel()
        for field in ('url','script','password','selector','cookies'):
            with self.assertRaises(core.ToolError):
                web_adapter.observe({'session_id':'a'*32,'requester':'owner',field:'private'})
        channel.request.assert_not_called()


class WebChannelTests(unittest.TestCase):
    def test_supervisor_waits_for_concurrent_channel_termination_before_closing_job(self):
        import web_channel
        import threading
        entered=threading.Event();release=threading.Event();finished=threading.Event()
        job=mock.Mock()
        def terminate():
            entered.set();release.wait(timeout=3)
        job.terminate.side_effect=terminate
        channel=web_channel.Channel(mock.Mock(poll=lambda:None),job,profile='p',requester='r',resource='q',deadline=1,config={})
        def supervisor_close():
            channel.close();job.close();finished.set()
        first=threading.Thread(target=channel.close);second=threading.Thread(target=supervisor_close)
        first.start();self.assertTrue(entered.wait(timeout=1));second.start()
        try:
            self.assertFalse(finished.wait(timeout=0.05));job.close.assert_not_called()
        finally:
            release.set();first.join(timeout=3);second.join(timeout=3)
        job.terminate.assert_called_once();job.close.assert_called_once()

    def test_timeout_terminates_owned_worker_without_replay(self):
        import web_channel
        process=mock.Mock(stdin=io.BytesIO(),stdout=io.BytesIO(),poll=lambda:None)
        channel=web_channel.Channel(process,mock.Mock(),profile='p',requester='r',resource='q',deadline=1,config={})
        channel._responses=mock.Mock()
        import queue
        channel._responses.get.side_effect=queue.Empty()
        with self.assertRaisesRegex(core.ToolError,'closed'):
            channel.request('observe',{},timeout=0.01)
        channel.job.terminate.assert_called_once()
        self.assertEqual(process.stdin.getvalue().count(b'\n'),1)


if __name__ == '__main__':
    unittest.main()
