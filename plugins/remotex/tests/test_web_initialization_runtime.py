from pathlib import Path
from unittest import mock
import json
import os
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import web_adapter
import pytest


@pytest.mark.skipif(os.name!='nt',reason='Windows native component protocol')
def test_actual_component_protocol_probe_opens_no_approval_window(monkeypatch):
    run=web_adapter.subprocess.run
    reports=[]
    def observed(command,**options):
        stage='worker' if '--describe-protocol' in command else 'native'
        try:
            result=run(command,**options)
        except subprocess.TimeoutExpired as error:
            reports.append((stage,'timeout',probe_stages(error.stderr)))
            raise
        reports.append((stage,result.returncode,len(result.stdout),probe_stages(result.stderr)))
        return result
    monkeypatch.setattr(web_adapter.subprocess,'run',observed)
    try:
        web_adapter._admit_v3_components(shutil.which('node'))
    except web_adapter.core.ToolError:
        pytest.fail(f'Component admission failed; fixed-stage diagnostics: {reports}',pytrace=False)


def probe_stages(stderr):
    if isinstance(stderr,bytes):stderr=stderr.decode('utf-8',errors='replace')
    allowed={f'protocol-probe: {name}' for name in
        ('forms','drawing','approval-ui','reference-review','functions','complete')}
    return [line for line in (stderr or '').splitlines() if line in allowed][-6:]


def test_probe_diagnostics_do_not_include_arbitrary_process_output():
    assert probe_stages(b'private-canary\nprotocol-probe: forms\nprivate-canary')==['protocol-probe: forms']


@pytest.mark.skipif(os.name!='nt',reason='Windows native module admission')
def test_native_protocol_does_not_depend_on_automatic_module_discovery():
    result=subprocess.run([web_adapter.credential_store._powershell_path(),'-NoLogo','-NoProfile',
        '-NonInteractive','-STA','-File',str(Path(__file__).with_name('Test-WebApprovalProtocol.ps1'))],
        stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='utf-8',timeout=10,
        env=web_adapter.credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0,probe_stages(result.stderr)
    assert json.loads(result.stdout)==web_adapter.V3_NATIVE_PROTOCOL


def test_v3_admission_requires_actual_worker_and_native_protocol_readbacks(monkeypatch):
    assert callable(getattr(web_adapter,'_admit_v3_components',None)), 'Missing mixed-component admission'
    worker={'setup_revisions':[1,2,3],'profiles':['json-utf8-v1','form-utf8-v1','form-json-name-view-v1'],
        'reference_units':32,'proposal_units':96,'transport':'fixed-egress-v1'}
    native={'protocol_revision':3,'reference_units':32,'review_seconds':180,'notification':'owned-native-v1'}
    from types import SimpleNamespace
    results=[SimpleNamespace(returncode=0,stdout=json.dumps(worker)),SimpleNamespace(returncode=0,stdout=json.dumps(native))]
    calls=[]
    def run(command,**options):calls.append(command);return results[len(calls)-1]
    monkeypatch.setattr(web_adapter.subprocess,'run',run)
    web_adapter._admit_v3_components('node')
    assert len(calls)==2 and '--describe-protocol' in calls[0] and '-DescribeProtocol' in calls[1]
    for part,key,value in [(worker,'setup_revisions',[1,2]),(native,'protocol_revision',2),(native,'reference_units',8)]:
        original=part[key];part[key]=value
        results[0].stdout=json.dumps(worker);results[1].stdout=json.dumps(native);calls.clear()
        with pytest.raises(web_adapter.core.ToolError,match='components'):
            web_adapter._admit_v3_components('node')
        part[key]=original


def test_installed_schema_does_not_claim_a_loaded_old_workers_v3_capability():
    from test_web_task_service import prepared
    service,channel,_=prepared()
    assert service.status()['setup_revisions']==[1,2]
    original=channel.request
    def request(operation,args,**options):
        value=original(operation,args,**options)
        if operation=='network-status':value['protocol']=web_adapter.V3_WORKER_PROTOCOL
        return value
    channel.request=request
    assert service.status()['setup_revisions']==[1,2,3]

def test_a_playwright_only_runtime_is_not_reported_ready_for_initialization(tmp_path):
    with (mock.patch.object(web_adapter,'_node',return_value='node'),
          mock.patch.object(web_adapter,'_module_path',return_value=tmp_path),
          mock.patch.object(web_adapter,'_parser_module_path',return_value=None,create=True)):
        value=json.loads(web_adapter.runtime_setup({'confirm':False})['content'][0]['text'])
    assert value['ready'] is False
    assert value['preview'] is True

def test_complete_pinned_runtime_remains_read_only_without_confirmation(tmp_path):
    with (mock.patch.object(web_adapter,'_node',return_value='node'),
          mock.patch.object(web_adapter,'_module_path',return_value=tmp_path),
          mock.patch.object(web_adapter,'_parser_module_path',return_value=tmp_path,create=True)):
        value=json.loads(web_adapter.runtime_setup({'confirm':False})['content'][0]['text'])
    assert value['ready'] is True
    assert value['installedNow'] is False
