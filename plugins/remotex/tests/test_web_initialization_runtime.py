from pathlib import Path
from unittest import mock
import json
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import web_adapter

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
