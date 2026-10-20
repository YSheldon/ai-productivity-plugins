from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from remotex_partial_order import PartialOrder


def permit(check):
    return {'authorization_reply':check,'allowed':True,'permit':{'kind':'initialization-read','expires_at_ms':10**15}}


@pytest.mark.parametrize('denied_first',[True,False])
def test_partial_fixture_preserves_original_denial_until_both_responses(denied_first):
    sent=[]
    channel=SimpleNamespace(config={'origin':'https://127.0.0.1:1'},_send=sent.append,on_startup=lambda frame:True)
    order=PartialOrder(channel)
    denial={'authorization_reply':'omitted','allowed':False}
    if denied_first:channel._send(denial)
    for check in ('one','two'):
        original=permit(check);channel._send(original)
        assert sent[-1]==original
        channel.on_startup({'kind':'prerequisite-response','check_id':check,'ready':True})
    if not denied_first:channel._send(denial)
    assert sent[-1]==denial and len(sent)==3
    channel.on_startup({'kind':'resume-ended'})
    order.finish()


def test_partial_fixture_does_not_accept_unknown_response_as_coverage():
    channel=SimpleNamespace(config={'origin':'https://127.0.0.1:1'},_send=lambda packet:None,on_startup=lambda frame:True)
    order=PartialOrder(channel)
    channel.on_startup({'kind':'prerequisite-response','check_id':'unknown','ready':True})
    assert not order.ready
    with pytest.raises(AssertionError):order.finish()


def test_partial_fixture_is_never_usable_for_a_real_site():
    with pytest.raises(AssertionError):PartialOrder(SimpleNamespace(config={'origin':'https://example.com'}))
