"""Cross App Access (ID-JAG) and A2A agent card signatures against the shared fake API: an app
trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
authorization server checks one (issuer, audience, client, expiry, typ, once); a card signed in
RFC 8785 form by the fake (JavaScript) verifies here with keys from its own host and fails when
changed or pointed elsewhere."""
import base64
import json
import time
import urllib.request

import pytest

from touchque import (
    AgentCardError, IdJagError, IdJagVerifier, canonical_json, redeem_id_jag, request_id_jag, sign_agent_card, verify_agent_card,
)

from .fake_api import fake_api  # noqa: F401 (fixture)


def _post(api, path, body):
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    return json.loads(urllib.request.urlopen(req).read() or b'{}')


def _get(url):
    return json.loads(urllib.request.urlopen(url).read())


def test_request_redeem_and_verify(fake_api):
    jag = request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='tqs_test', id_token='idtoken:ada',
                         audience='https://rs.example', resource='https://rs.example/files')
    assert jag['scope'] == 'files:read'
    with pytest.raises(IdJagError) as e:
        request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='wrong', id_token='idtoken:ada', audience='https://rs.example')
    assert (e.value.code, e.value.status) == ('invalid_client', 401)
    with pytest.raises(IdJagError) as e:
        request_id_jag(issuer=fake_api.base_url + '/idp', client_id='tqapp_test', client_secret='tqs_test', id_token='idtoken:ada', audience='https://other.example')
    assert e.value.code == 'invalid_target'

    verifier = IdJagVerifier(issuer=fake_api.base_url + '/idp', audience='https://rs.example')
    claims = verifier.verify(jag['assertion'], client_id='acme-at-rs')
    assert (claims['sub'], claims['client_id'], claims['scopes'], claims['resource']) == ('ada', 'acme-at-rs', ['files:read'], 'https://rs.example/files')
    with pytest.raises(IdJagError, match='already used'):
        verifier.verify(jag['assertion'], client_id='acme-at-rs')
    tokens = redeem_id_jag(token_endpoint=fake_api.base_url + '/rs/token', client_id='acme-at-rs', assertion=jag['assertion'])
    assert tokens['token_type'] == 'Bearer'


def test_refusals(fake_api):
    verifier = IdJagVerifier(issuer=fake_api.base_url + '/idp', audience='https://rs.example')

    def mint(claims=None, typ=None):
        return _post(fake_api, '/__test/id-jag', {'claims': claims or {}, **({'typ': typ} if typ else {})})['assertion']

    def reason(assertion, client_id='acme-at-rs'):
        try:
            verifier.verify(assertion, client_id=client_id)
            return 'accepted'
        except IdJagError as err:
            return str(err)

    assert reason(mint(), 'someone-else') == 'issued to another client'
    assert reason(mint({'aud': 'https://evil.example'})) == 'not for this authorization server'
    assert reason(mint({'aud': ['https://rs.example', 'https://b.example']})) == 'not for this authorization server'
    assert reason(mint({'iss': 'https://evil.example'})) == 'another issuer'
    assert reason(mint(typ='at+jwt')) == 'not an ID-JAG (typ oauth-id-jag+jwt)'
    assert reason(mint({'exp': int(time.time()) - 600})) == 'expired'
    head, body, sig = mint().split('.')
    claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
    forged = base64.urlsafe_b64encode(json.dumps({**claims, 'sub': 'mallory'}).encode()).rstrip(b'=').decode()
    assert reason(f'{head}.{forged}.{sig}') == 'signature does not verify'
    # A signature segment that is not base64url is a malformed JWT, never a ValueError.
    assert reason(f'{head}.{body}.é') == 'assertion is not a JWT'
    assert reason(f'{head}.{body}.a') == 'assertion is not a JWT'


def test_agent_card_from_the_fake(fake_api):
    url = fake_api.base_url + '/.well-known/agent-card.json'
    card = _get(url)
    assert verify_agent_card(card, card_url=url) == {'kid': 'a2a-1', 'alg': 'ES256', 'key_source': 'jku'}
    with pytest.raises(AgentCardError) as e:
        verify_agent_card(_get(url + '?tamper=1'), card_url=url)
    assert e.value.code == 'invalid_signature'
    with pytest.raises(AgentCardError) as e:
        verify_agent_card(card, card_url='https://agent.example/.well-known/agent-card.json')
    assert e.value.code == 'untrusted_key'
    with pytest.raises(AgentCardError) as e:
        verify_agent_card({'name': 'x'})
    assert e.value.code == 'unsigned'


def test_sign_and_canonical_form():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_agent_card({'name': 'Mine', 'url': 'https://mine.example/a2a', 'skills': []}, key, kid='k1')
    raw = key.public_key().public_bytes_raw() if hasattr(key.public_key(), 'public_bytes_raw') else None
    if raw is None:
        from cryptography.hazmat.primitives import serialization
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'x': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(), 'kid': 'k1'}
    assert verify_agent_card(signed, keys=[jwk]) == {'kid': 'k1', 'alg': 'EdDSA', 'key_source': 'keys'}
    with pytest.raises(AgentCardError):
        verify_agent_card({**signed, 'url': 'https://evil.example/a2a'}, keys=[jwk])
    with pytest.raises(AgentCardError) as e:
        verify_agent_card({**signed, 'signatures': [{**signed['signatures'][0], 'signature': 'é'}]}, keys=[jwk])
    assert e.value.code == 'invalid_signature'
    assert canonical_json({'€': 'Euro', '\r': 'CR', '\U0001F600': 'smile', '1': 'one', 'a': [1e21, 1e-7, 0.5, -0.0, 'tab\there', 1e-5, 100.0]}) == \
        '{"\\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\\there",0.00001,100],"€":"Euro","😀":"smile"}'
