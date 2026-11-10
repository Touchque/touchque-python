"""A2A agent card signatures (A2A 1.0 §8.4).

Before your agent trusts another agent's card (its name, URL, skills), check
that whoever controls its keys signed exactly this card. Each entry of
``signatures`` is a JWS (RFC 7515) over the card in RFC 8785 canonical form
without ``signatures``; the protected header names alg, kid and optionally
jku (where the keys are)::

    card = requests.get('https://agent.example/.well-known/agent-card.json').json()
    verify_agent_card(card, card_url='https://agent.example/.well-known/agent-card.json')

Keys come from ``keys`` (a JWKS you trust) or from the header's jku, but jku
is only followed on the card's own host (or a host in ``trusted_jku_hosts``):
a card that points at keys on a host of its choosing proves nothing. Signers
must leave out fields at their default values (A2A §8.4.1); the card is
checked as received.

Needs the optional ``cryptography`` package: ``pip install "touchque-authenticator[agent]"``.
"""

import json
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union
from urllib.parse import urlparse

import requests

from .mcp_auth import _b64d, _b64e, _json_part, _public_key, _verify

__all__ = ['AgentCardError', 'canonical_json', 'verify_agent_card', 'sign_agent_card']

_ALGS = ('RS256', 'ES256', 'EdDSA')


class AgentCardError(Exception):
    """``code``: unsigned | malformed | untrusted_key | invalid_signature | keys_unavailable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _es_number(value: float) -> str:
    """A number as ECMAScript's Number::toString writes it (RFC 8785 §3.2.2.3)."""
    if value != value or value in (float('inf'), float('-inf')):
        raise AgentCardError('malformed', 'a number is not finite')
    if value == 0:
        return '0'
    sign = '-' if value < 0 else ''
    t = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = ''.join(str(d) for d in t.digits)
    k = len(digits)
    n = t.exponent + k
    if k <= n <= 21:
        out = digits + '0' * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + '.' + digits[n:]
    elif -6 < n <= 0:
        out = '0.' + '0' * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ('.' + digits[1:] if k > 1 else '') + 'e' + ('+' if e >= 0 else '-') + str(abs(e))
    return sign + out


def canonical_json(value: Any) -> str:
    """RFC 8785 (JSON Canonicalization Scheme): sorted keys (UTF-16 order), no whitespace, ECMAScript numbers."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _es_number(value)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(canonical_json(v) for v in value) + ']'
    if isinstance(value, Mapping):
        keys = sorted(value.keys(), key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + canonical_json(value[k]) for k in keys) + '}'
    raise AgentCardError('malformed', f'cannot canonicalize {type(value).__name__}')


def _payload(card: Mapping[str, Any]) -> str:
    rest = {k: v for k, v in card.items() if k != 'signatures'}
    return _b64e(canonical_json(rest).encode('utf-8'))


def _host_of(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    u = urlparse(url)
    local = u.hostname in ('localhost', '127.0.0.1', '::1')
    if u.scheme != 'https' and not (u.scheme == 'http' and local):
        return None
    return u.netloc


def verify_agent_card(card: Union[Mapping[str, Any], str], card_url: Optional[str] = None,
                      keys: Union[Iterable[Mapping[str, Any]], Mapping[str, Any], None] = None,
                      trusted_jku_hosts: Optional[List[str]] = None) -> Dict[str, str]:
    """Checks the card's signatures: ``{'kid', 'alg', 'key_source': 'keys' | 'jku'}`` or AgentCardError."""
    try:
        c = json.loads(card) if isinstance(card, str) else card
    except ValueError:
        raise AgentCardError('malformed', 'the card is not JSON')
    if not isinstance(c, Mapping):
        raise AgentCardError('malformed', 'the card is not a JSON object')
    sigs = c.get('signatures')
    if not isinstance(sigs, list) or not sigs:
        raise AgentCardError('unsigned', 'the card has no signatures')
    given = list((keys.get('keys') or []) if isinstance(keys, Mapping) else (keys or []))
    card_host = _host_of(card_url)
    payload = _payload(c)
    last = AgentCardError('invalid_signature', 'no signature verifies')
    for s in sigs:
        if not isinstance(s, Mapping) or not isinstance(s.get('protected'), str) or not isinstance(s.get('signature'), str):
            continue
        try:
            head = _json_part(s['protected'])
        except ValueError:
            continue
        alg = head.get('alg')
        if alg not in _ALGS or not isinstance(head.get('kid'), str) or 'crit' in head:
            continue
        if 'typ' in head and head['typ'] != 'JOSE':
            continue
        jwk = next((k for k in given if k.get('kid') == head['kid']), None)
        source = 'keys'
        if jwk is None and isinstance(head.get('jku'), str):
            jku_host = _host_of(head['jku'])
            if not jku_host or (jku_host != card_host and jku_host not in (trusted_jku_hosts or [])):
                last = AgentCardError('untrusted_key', f"jku {head['jku']} is not on the card's host")
                continue
            try:
                r = requests.get(head['jku'], timeout=5, allow_redirects=False)
                if r.status_code != 200:
                    raise RuntimeError(f'it answered {r.status_code}')
                jwk = next((k for k in r.json().get('keys', []) if k.get('kid') == head['kid']), None)
            except Exception as err:
                last = AgentCardError('keys_unavailable', f"the keys at {head['jku']} could not be read: {err}")
                continue
            source = 'jku'
        if jwk is None:
            if last.code == 'invalid_signature':
                last = AgentCardError('untrusted_key', f"no trusted key {head['kid']}")
            continue
        try:
            key = _public_key(jwk)
        except (ValueError, KeyError):
            continue
        try:
            sig = _b64d(s['signature'])
        except ValueError:  # not base64url (e.g. non-ASCII): a signature that does not verify
            sig = b''
        if _verify(f"{s['protected']}.{payload}".encode(), sig, alg, key):
            return {'kid': head['kid'], 'alg': alg, 'key_source': source}
        last = AgentCardError('invalid_signature', 'the signature does not match the card')
    raise last


def sign_agent_card(card: Mapping[str, Any], private_key, kid: str, jku: Optional[str] = None) -> Dict[str, Any]:
    """Signs a card you publish: returns it with one more entry in ``signatures`` (EC P-256, Ed25519 or RSA key)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        alg = 'ES256'
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        alg = 'EdDSA'
    elif isinstance(private_key, rsa.RSAPrivateKey):
        alg = 'RS256'
    else:
        raise AgentCardError('malformed', 'the key must be EC P-256, Ed25519 or RSA')
    header = {'alg': alg, 'typ': 'JOSE', 'kid': kid, **({'jku': jku} if jku else {})}
    protected = _b64e(json.dumps(header, separators=(',', ':')).encode())
    data = f'{protected}.{_payload(card)}'.encode()
    if alg == 'ES256':
        r, s = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    elif alg == 'EdDSA':
        sig = private_key.sign(data)
    else:
        sig = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    prior = list(card.get('signatures') or [])
    return {**card, 'signatures': prior + [{'protected': protected, 'signature': _b64e(sig)}]}
