"""A code typed back on the phone (login.request(reply=...)) against the shared fake TouchQue API,
which seals it like the phone does: it opens only with the one-time key, for that request."""
import json
import urllib.request

from touchque import Config, TouchQue, new_code_reply_key, open_code_reply
from .fake_api import fake_api  # noqa: F401 (fixture)


def _post(fake_api, path, body):
    req = urllib.request.Request(fake_api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def test_the_typed_code_opens_only_with_the_one_time_key_for_that_request(fake_api):
    fake_api.link('ayse@acme.com')
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
    key = new_code_reply_key()
    sent = tq.login.request('ayse@acme.com', reply={'kind': 'code', 'key': key['public_key'], 'channel': 'sms', 'target': '+**********26'})
    assert 'reply' not in tq.login.status(sent['requestId'])
    _post(fake_api, '/__test/approve', {'id': sent['requestId'], 'replyCode': '482 913'})
    ct = tq.login.status(sent['requestId'])['reply']['ct']
    assert open_code_reply(key['private_key'], sent['requestId'], ct) == '482 913'
    assert open_code_reply(key['private_key'], 'another-request', ct) is None
    assert open_code_reply(new_code_reply_key()['private_key'], sent['requestId'], ct) is None
    assert open_code_reply(key['private_key'], sent['requestId'], 'v1.bad.ct') is None
