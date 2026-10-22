from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import time
import io
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import credential_store
import profile_config
import remotex_core as core
import remotex_mcp


class WebCredentialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "config.json"
        self.path.write_text(json.dumps({"version":2,"credentials":{},"profiles":{},"defaults":{}}))
        patch = mock.patch.dict(os.environ, {"REMOTEX_CONFIG":str(self.path),"REMOTEX_WEB_STATE_DIR":str(self.root / "web"),"REMOTEX_VM_QUEUE_FILE":str(self.root / 'queue.json'),"REMOTEX_VM_QUEUE_LEASE_FILE":str(self.root / 'leases.json'),"REMOTEX_AUDIT_FILE":str(self.root / 'audit.jsonl')})
        patch.start()
        self.addCleanup(patch.stop)
        self.args = {"profile":"web-lab","kind":"web","url":"https://console.example:6868/#/",
            "account":"security","credential_ref":"web-security","credential_source":"windows-credential-manager",
            "username_selector":"#loginName","password_selector":"#loginPass","submit_selector":"#loginBtn",
            "confirm":False}

    def prepared(self):
        return profile_config.prepare(self.args)

    def test_web_profile_has_origin_account_bound_credential_and_queue(self):
        p = self.prepared()
        self.assertEqual(p.profile["origin"], "https://console.example:6868")
        self.assertEqual(p.record["web_account"], "security")
        self.assertEqual(p.record["web_origin"], "https://console.example:6868")
        self.assertTrue(p.record["target"].startswith("RemoteX/Web/"))
        self.assertTrue(p.profile["queue_resource"].startswith("web:"))
        self.assertNotIn("password", p.record)
        self.assertEqual(json.loads(self.path.read_text())["profiles"], {})

    def test_certificate_pin_is_explicit_normalized_and_origin_bound(self):
        p = profile_config.prepare({**self.args, "certificate_sha256": "AB:" * 31 + "AB"})
        self.assertEqual(p.profile["certificate_sha256"], "ab" * 32)
        bundle = core.ConfigBundle(p.candidate, self.path, "remotex", True)
        credential_store.resolve_profile_reference(bundle, "web-lab", p.profile, "web")
        p.candidate["profiles"]["web-lab"]["origin"] = "https://other.example:6868"
        with self.assertRaises(core.ToolError):
            core._validate_config(p.candidate)

    def test_invalid_certificate_pins_cannot_enable_a_trust_exception(self):
        for pin in ("", "a" * 63, "z" * 64, True, "*", "ab:" * 32, " a" * 32):
            with self.subTest(pin=pin), self.assertRaises(core.ToolError):
                profile_config.prepare({**self.args, "certificate_sha256": pin})

    def test_existing_web_profiles_remain_strict_without_a_pin(self):
        p = self.prepared()
        self.assertNotIn("certificate_sha256", p.profile)
        core._validate_config(p.candidate)

    def test_certificate_trust_preview_write_and_revoke_are_exact_origin_scoped(self):
        import web_adapter
        self.assertTrue(callable(getattr(web_adapter, "certificate_trust", None)))
        p = self.prepared()
        self.path.write_text(json.dumps(p.candidate))
        before = self.path.read_bytes()
        args = {"profile": "web-lab", "origin": "https://console.example:6868",
                "certificate_sha256": "ab" * 32, "confirm": False}
        preview = json.loads(web_adapter.certificate_trust(args)["content"][0]["text"])
        self.assertTrue(preview["preview"])
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(core.ToolError):
            web_adapter.certificate_trust({**args, "origin": "https://console.example", "confirm": True})
        self.assertEqual(self.path.read_bytes(), before)
        stored = json.loads(web_adapter.certificate_trust({**args, "confirm": True})["content"][0]["text"])
        self.assertTrue(stored["configurationStored"])
        self.assertEqual(core.load_config().data["profiles"]["web-lab"]["certificate_sha256"], "ab" * 32)
        web_adapter.certificate_trust({**args, "certificate_sha256": None, "confirm": True})
        self.assertNotIn("certificate_sha256", core.load_config().data["profiles"]["web-lab"])

    def test_certificate_trust_cannot_change_during_an_active_browser_session(self):
        import web_adapter
        self.assertTrue(callable(getattr(web_adapter, "certificate_trust", None)))
        self.path.write_text(json.dumps(self.prepared().candidate))
        before = self.path.read_bytes()
        with mock.patch.object(web_adapter, "assert_resource_idle", side_effect=core.ToolError("active web session")):
            with self.assertRaisesRegex(core.ToolError, "active web session"):
                web_adapter.certificate_trust({"profile": "web-lab", "origin": "https://console.example:6868",
                    "certificate_sha256": "ab" * 32, "confirm": True})
        self.assertEqual(self.path.read_bytes(), before)

    def test_login_rechecks_trust_after_acquiring_the_resource_lock(self):
        import web_adapter, queue_leases
        p = profile_config.prepare({**self.args, "certificate_sha256": "ab" * 32})
        self.path.write_text(json.dumps(p.candidate))

        @contextmanager
        def rotate_before_acquisition(resource, requester):
            web_adapter.certificate_trust({"profile": "web-lab", "origin": p.profile["origin"],
                "certificate_sha256": None, "confirm": True})
            yield {"lease": {"remainingSeconds": 1800}}

        with (mock.patch.object(web_adapter, "_node", return_value="node"),
              mock.patch.object(web_adapter, "_module_path", return_value=self.root),
              mock.patch.object(queue_leases, "leased_owner_operation", rotate_before_acquisition),
              mock.patch.object(core, "read_windows_generic_credential", side_effect=AssertionError("must not read credentials after trust changed"))):
            with self.assertRaisesRegex(core.ToolError, "changed"):
                web_adapter.login({"profile": "web-lab", "requester": "owner", "confirm": True})

    def test_setup_rejects_unsafe_origin_and_selector_inputs(self):
        for url in ("http://console.example/", "https://user:secret@console.example/", "https://console.example/?token=x", "https://console.example\\@evil.example/", "file:///x"):
            with self.subTest(url=url), self.assertRaises(core.ToolError):
                profile_config.prepare({**self.args,"url":url})
        with self.assertRaises(core.ToolError):
            profile_config.prepare({**self.args,"password_selector":"body"})

    def test_long_session_requires_full_lease_before_reading_credentials(self):
        import web_adapter, queue_leases
        self.path.write_text(json.dumps(self.prepared().candidate))
        @contextmanager
        def short_lease(resource, requester):
            yield {'lease': {'remainingSeconds': 46844}}
        with (mock.patch.object(web_adapter, '_node', return_value='node'),
              mock.patch.object(web_adapter, '_module_path', return_value=self.root),
              mock.patch.object(queue_leases, 'leased_owner_operation', short_lease),
              mock.patch.object(core, 'read_windows_generic_credential', side_effect=AssertionError('credential read before covering lease'))):
            with self.assertRaisesRegex(core.ToolError, 'cover session_seconds plus 45'):
                web_adapter.login({'profile': 'web-lab', 'requester': 'owner', 'confirm': True, 'session_seconds': 46800})

    def test_incomplete_parser_runtime_blocks_login_before_credential_read(self):
        import web_adapter, queue_leases
        self.path.write_text(json.dumps(self.prepared().candidate))
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':1800})
        with (mock.patch.object(web_adapter,'_node',return_value='node'),
              mock.patch.object(web_adapter,'_module_path',return_value=self.root),
              mock.patch.object(web_adapter,'_parser_module_path',return_value=None,create=True),
              mock.patch.object(core,'read_windows_generic_credential',side_effect=AssertionError('incomplete runtime must not read a credential'))):
            with self.assertRaisesRegex(core.ToolError,'runtime_setup'):
                web_adapter.login({'profile':'web-lab','requester':'owner','confirm':True,'session_seconds':900})

    def test_site_protocol_upgrade_is_required_before_credentials_or_browser_start(self):
        import web_adapter, queue_leases
        self.path.write_text(json.dumps(self.prepared().candidate))
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':1800})
        with (mock.patch.object(web_adapter,'_node',return_value='node'),
              mock.patch.object(web_adapter,'_module_path',return_value=self.root),
              mock.patch.object(web_adapter,'_parser_module_path',return_value=self.root),
              mock.patch.object(core,'read_windows_generic_credential',side_effect=AssertionError('credential read')),
              mock.patch.object(web_adapter.subprocess,'Popen',side_effect=AssertionError('browser started'))):
            with self.assertRaisesRegex(core.ToolError,'remotex_web_authorization_upgrade'):
                web_adapter.login({'profile':'web-lab','requester':'owner','confirm':True,'session_seconds':900})
        self.assertFalse((self.root/'web'/'authorization').exists())

    def test_key_only_diagnostic_never_reads_credentials_or_relabels_invalid_key(self):
        import web_adapter, queue_leases
        self.path.write_text(json.dumps(self.prepared().candidate))
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':1800})
        root=self.root/'web'/'authorization';root.mkdir(parents=True)
        with (mock.patch.object(web_adapter,'_node',return_value='node'),
              mock.patch.object(web_adapter,'_module_path',return_value=self.root),
              mock.patch.object(web_adapter,'_parser_module_path',return_value=self.root),
              mock.patch.object(core,'read_windows_generic_credential',side_effect=AssertionError('credential read')),
              mock.patch.object(web_adapter.subprocess,'Popen',side_effect=AssertionError('browser started'))):
            for size,code in ((32,'recovery-state-missing'),(1,'recovery-key-invalid')):
                (root/'integrity.key').write_bytes(b'x'*size)
                with self.subTest(size=size),self.assertRaisesRegex(core.ToolError,code):
                    web_adapter.login({'profile':'web-lab','requester':'owner','confirm':True,'session_seconds':900})
                self.assertFalse((root/'uncertain-writes.json').exists())

    def test_default_long_session_packet_and_public_result_share_the_thirteen_hour_bound(self):
        import web_adapter, queue_leases
        self.path.write_text(json.dumps(self.prepared().candidate))
        queue_leases.queue_acquire({'profile': 'web-lab', 'requester': 'owner', 'lease_seconds': 46900})
        process = mock.Mock(pid=123, stdin=io.BytesIO())
        process.poll.return_value = None
        job = mock.Mock(assigned=True)
        identifier = None
        try:
            with (mock.patch.object(web_adapter, '_node', return_value='node'),
                  mock.patch.object(web_adapter, '_module_path', return_value=self.root),
                  mock.patch.object(web_adapter, '_admit_v3_components', return_value=None),
                  mock.patch.object(web_adapter.web_site_service.ApprovalPrompt, 'start',
                      return_value=mock.Mock(status=lambda:{'state':'shown','shown':True,'review_remaining_seconds':180})),
                  mock.patch.object(web_adapter.secure_paths, 'ensure_private_directory', side_effect=lambda p: p.mkdir(parents=True, exist_ok=True)),
                  mock.patch.object(web_adapter.secure_paths, 'ensure_private_file', return_value=None),
                  mock.patch.object(web_adapter.subprocess, 'Popen', return_value=process),
                  mock.patch.object(web_adapter.execution, '_WindowsJob', return_value=job),
                  mock.patch.object(web_adapter.threading.Thread, 'start', return_value=None),
                  mock.patch.object(core, 'read_windows_generic_credential', return_value=core.CredentialValue('security', 'synthetic-long-session-canary'))):
                web_adapter.authorization_upgrade({'confirm':True})
                before = int(time.time() * 1000)
                result = json.loads(web_adapter.login({'profile': 'web-lab', 'requester': 'owner', 'confirm': True})['content'][0]['text'])
                identifier = result['webSessionId']
                packet = json.loads(process.stdin.getvalue())
                self.assertEqual(packet['authorization_mode'], 'site')
                self.assertEqual(result['authorizationMode'], 'site')
                self.assertEqual(result['nextStep'], 'approve-local-site-window')
                self.assertEqual(result['sessionSeconds'], 46800)
                self.assertGreaterEqual(packet['deadline'], before + 46800000)
                self.assertLessEqual(packet['deadline'], int(time.time() * 1000) + 46800000)
                for file in (self.root / 'web').rglob('*.json'):
                    self.assertNotIn('synthetic-long-session-canary', file.read_text())
        finally:
            if identifier:
                with web_adapter._CHANNELS_LOCK:
                    channel = web_adapter._CHANNELS.pop(identifier, None)
                if channel:
                    channel.close()
            job.close()

    def test_origin_or_account_changes_cannot_reuse_saved_target(self):
        p = self.prepared()
        candidate = p.candidate
        candidate["profiles"]["web-lab"]["url"] = "https://different.example/"
        with self.assertRaises(core.ToolError):
            core._validate_config(candidate)

    def test_web_credential_cannot_be_reused_for_winrm(self):
        p = self.prepared()
        p.candidate["profiles"]["guest"] = {"kind":"windows-guest","credential_ref":"web-security"}
        with self.assertRaises(core.ToolError):
            core._validate_config(p.candidate)

    def test_existing_credential_store_reuses_secure_prompt_with_expected_account(self):
        p = self.prepared()
        bundle = core.ConfigBundle(p.candidate,self.path,"remotex",True)
        reference = credential_store.resolve_profile_reference(bundle,"web-lab",p.profile,"web")
        arguments = credential_store._setup_arguments(reference,self.root / "receipt.json")
        self.assertIn("-ExpectedUser", arguments)
        self.assertEqual(arguments[arguments.index("-ExpectedUser")+1], "security")
        self.assertEqual(arguments[arguments.index("-ScopeLabel")+1], "https://console.example:6868")

    def test_web_tools_accept_no_password_or_arbitrary_browser_commands(self):
        for name in ("remotex_web_login","remotex_web_session_status","remotex_web_session_close"):
            self.assertTrue(name in remotex_mcp.TOOLS, name)
            fields = remotex_mcp.TOOLS[name]["inputSchema"]["properties"]
            self.assertFalse(set(fields) & {"password","script","javascript","target","cookies","debug_port"})

    def test_session_status_keeps_web_identifier_separate_from_audit_identifier(self):
        import web_adapter
        identifier = 'a' * 32
        directory = self.root / 'web' / 'sessions' / identifier
        directory.mkdir(parents=True)
        (directory / 'session.json').write_text(json.dumps({'profile':'web-lab','requester':'test','queueResource':'web:'+'b'*64,'originSha256':'b'*64,'deadline':9999999999999}))
        (directory / 'state.json').write_text(json.dumps({'state':'closed','loginSubmitted':True,'authenticationVerified':False,'failureCode':None,'updatedAt':'2026-10-11T01:00:00Z'}))
        result = web_adapter.session_status({'session_id':identifier})
        import audit_log
        value = json.loads(audit_log.attach_metadata(result,'operation')['content'][0]['text'])
        self.assertEqual(value['webSessionId'], identifier)

    def test_session_state_rejects_unexpected_secret_fields(self):
        import web_adapter
        directory = self.root / 'state'
        directory.mkdir()
        (directory / 'state.json').write_text(json.dumps({'state':'failed','password':'secret-canary'}))
        with self.assertRaises(core.ToolError) as caught:
            web_adapter._state(directory)
        self.assertNotIn('secret-canary', str(caught.exception))

    def test_reserved_target_cannot_omit_binding_metadata(self):
        target = self.prepared().record['target']
        for value in (target,target.lower(),target.upper()):
            with self.subTest(value=value), self.assertRaises(core.ToolError):
                credential_store._validate_record({'source':'windows-credential-manager','target':value},'credential')

    def test_legacy_inline_web_binding_cannot_resolve_for_another_protocol(self):
        record = self.prepared().record
        for kind in ('windows-guest','rdp','vsphere'):
            raw={'kind':kind,'credential':record}
            bundle=core.ConfigBundle({'version':1,'profiles':{'legacy':raw},'defaults':{}},self.path,'remotex',True)
            with self.subTest(kind=kind), self.assertRaises(core.ToolError):
                credential_store.resolve_profile_reference(bundle,'legacy',raw,kind)

    def test_zero_port_is_rejected(self):
        with self.assertRaises(core.ToolError):
            profile_config.prepare({**self.args,'url':'https://console.example:0/'})

    def test_active_session_blocks_release_but_allows_fifo_waiter_registration(self):
        import web_adapter, queue_leases
        p = self.prepared()
        self.path.write_text(json.dumps(p.candidate))
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':300})
        directory = self.root / 'web' / 'active'
        directory.mkdir(parents=True)
        marker = directory / (p.profile['queue_resource'][4:]+'.json')
        marker.write_text(json.dumps({'webSessionId':'a'*32,'processId':123,'supervisorId':456}))
        with mock.patch.object(web_adapter,'_running_or_unknown',return_value=True):
            with self.assertRaisesRegex(core.ToolError,'active web session'):
                queue_leases.queue_release({'profile':'web-lab','requester':'owner'})
            queued = json.loads(queue_leases.queue_request({'profile':'web-lab','requester':'next'})['content'][0]['text'])
            self.assertEqual(queued['requester_position'],1)
        marker.unlink()
        result = json.loads(queue_leases.queue_release({'profile':'web-lab','requester':'owner'})['content'][0]['text'])
        self.assertIsNone(result['owner'])

    def test_other_requester_cannot_close_session(self):
        import web_adapter
        identifier='a'*32
        directory=self.root / 'web' / 'sessions' / identifier
        directory.mkdir(parents=True)
        (directory / 'session.json').write_text(json.dumps({'profile':'web-lab','requester':'owner','queueResource':'web:'+'b'*64,'originSha256':'b'*64,'deadline':9999999999999}))
        with self.assertRaises(core.ToolError):
            web_adapter.close_session({'session_id':identifier,'requester':'other','confirm':True})
        self.assertFalse((directory / 'close.request').exists())
        value=json.loads(web_adapter.close_session({'session_id':identifier,'requester':'owner','confirm':True})['content'][0]['text'])
        self.assertTrue(value['closeRequested'])

    def test_legacy_web_prefix_resource_is_not_a_managed_browser_session(self):
        import web_adapter
        web_adapter.assert_resource_idle('web:legacy-host')

    def test_shortened_lease_no_longer_covers_live_session(self):
        import web_adapter, queue_leases
        p=self.prepared();self.path.write_text(json.dumps(p.candidate))
        resource=p.profile['queue_resource']
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':600})
        deadline=int((time.time()+120)*1000)
        self.assertTrue(web_adapter._lease_covers(resource,'owner',deadline))
        queue_leases.queue_renew({'profile':'web-lab','requester':'owner','lease_seconds':60})
        self.assertFalse(web_adapter._lease_covers(resource,'owner',deadline))

    def test_closed_job_proof_allows_cleanup_while_supervisor_is_alive(self):
        import web_adapter
        resource='web:'+'b'*64;identifier='a'*32
        directory=self.root / 'web' / 'sessions' / identifier;directory.mkdir(parents=True)
        marker=web_adapter._active_path(resource);marker.parent.mkdir(parents=True)
        proof={'webSessionId':identifier,'processId':123,'supervisorId':456}
        marker.write_text(json.dumps(proof));(directory/'closed.json').write_text(json.dumps(proof))
        with mock.patch.object(web_adapter,'_running_or_unknown',return_value=True):
            web_adapter.assert_resource_idle(resource)
        self.assertFalse(marker.exists())

    def test_supervisor_start_failure_cleans_job_marker_and_keeps_password_off_disk(self):
        import web_adapter, queue_leases
        p=self.prepared();self.path.write_text(json.dumps(p.candidate))
        queue_leases.queue_acquire({'profile':'web-lab','requester':'owner','lease_seconds':1800})
        process=mock.Mock(pid=123,stdin=io.BytesIO());process.poll.return_value=None
        job=mock.Mock(assigned=True)
        with (
            mock.patch.object(web_adapter,'_node',return_value='node'),
            mock.patch.object(web_adapter,'_module_path',return_value=self.root),
            mock.patch.object(web_adapter,'_admit_v3_components',return_value=None),
            mock.patch.object(web_adapter.secure_paths,'ensure_private_directory',side_effect=lambda p:p.mkdir(parents=True,exist_ok=True)),
            mock.patch.object(web_adapter.secure_paths,'ensure_private_file',return_value=None),
            mock.patch.object(web_adapter.subprocess,'Popen',return_value=process),
            mock.patch.object(web_adapter.execution,'_WindowsJob',return_value=job),
            mock.patch.object(web_adapter.threading.Thread,'start',side_effect=RuntimeError('no thread')),
            mock.patch.object(core,'read_windows_generic_credential',return_value=core.CredentialValue('security','synthetic-secret-canary')),
        ):
            web_adapter.authorization_upgrade({'confirm':True})
            with self.assertRaises(core.ToolError):
                web_adapter.login({'profile':'web-lab','requester':'owner','confirm':True,'session_seconds':900})
        self.assertFalse(web_adapter._active_path(p.profile['queue_resource']).exists())
        self.assertTrue(job.close.called)
        for file in (self.root/'web').rglob('*.json'):
            self.assertNotIn('synthetic-secret-canary',file.read_text())


if __name__ == "__main__":
    unittest.main()
