"""What a partner's server checks before executing what an AI agent asked
for: the approval token's claims match the transaction (person, action type,
authorization details), and, offline, its ES256 signature against TouchQue's
keys (GET /agents/jwks.json).

Matching rules (fixtures/agent-vectors.json): every expected field must be
equal, extra fields are ignored; amounts compare as decimals ("500" =
"500.00"), IBANs without spaces and in any case, currencies in any case; a
dict matches a token with exactly one entry, a list matches entry by entry
with the same length.
"""
import base64
import json
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Union

from .exceptions import TouchQueApprovalMismatchError

__all__ = ['matches_authorization_details', 'assert_approval_matches', 'decode_approval_token', 'verify_approval_token_with']

Expected = Union[Mapping[str, Any], List[Mapping[str, Any]]]


def _decimal(value: Any) -> Optional[str]:
    text = str(value).strip()
    if not re.match(r'^\d+(\.\d+)?$', text):
        return None
    whole, _, frac = text.partition('.')
    whole = whole.lstrip('0') or '0'
    frac = frac.rstrip('0')
    return f'{whole}.{frac}' if frac else whole


def _same(key: str, actual: Any, expected: Any) -> bool:
    if isinstance(expected, (dict, list)):
        return _partial(actual, expected)
    if key == 'amount':
        return _decimal(actual) is not None and _decimal(actual) == _decimal(expected)
    if key in ('iban', 'currency'):
        return isinstance(actual, str) and re.sub(r'\s+', '', actual).upper() == re.sub(r'\s+', '', str(expected)).upper()
    return actual == expected and type(actual) is type(expected)


def _partial(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            _partial(a, e) if isinstance(e, dict) else a == e for a, e in zip(actual, expected))
    if not isinstance(actual, dict):
        return False
    return all(k in actual and _same(k, actual[k], v) for k, v in expected.items())


def matches_authorization_details(details: Any, expected: Expected) -> bool:
    """Does ``details`` (a token's authorization_details) say what ``expected`` says?"""
    if not isinstance(details, list):
        return False
    if isinstance(expected, list):
        return len(details) == len(expected) and all(_partial(d, e) for d, e in zip(details, expected))
    return len(details) == 1 and _partial(details[0], expected)


def assert_approval_matches(claims: Mapping[str, Any], user: Optional[str] = None, type: Optional[str] = None,
                            authorization_details: Optional[Expected] = None) -> None:
    """Raises TouchQueApprovalMismatchError unless the claims say what you expect."""
    if user is not None and claims.get('sub') != user:
        raise TouchQueApprovalMismatchError("the approval is for another person")
    if type is not None and claims.get('type') != type:
        raise TouchQueApprovalMismatchError(f"the approval is for another action type ({claims.get('type')})")
    if authorization_details is not None and not matches_authorization_details(claims.get('authorization_details'), authorization_details):
        raise TouchQueApprovalMismatchError('the approved details differ from what you are about to execute')


def _b64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))


def decode_approval_token(token: str) -> Dict[str, Any]:
    """``{'header': ..., 'claims': ...}`` WITHOUT checking the signature."""
    parts = token.split('.') if isinstance(token, str) else []
    if len(parts) != 3:
        raise TouchQueApprovalMismatchError('not an approval token')
    try:
        return {'header': json.loads(_b64(parts[0])), 'claims': json.loads(_b64(parts[1]))}
    except (ValueError, TypeError) as exc:
        raise TouchQueApprovalMismatchError('not an approval token') from exc


def verify_approval_token_with(token: str, jwks: Mapping[str, Any], audience: Optional[str] = None,
                               now: Optional[float] = None, **expect: Any) -> Dict[str, Any]:
    """Verifies an approval token offline: typ touchque-approval+jwt, ES256 by
    a key of ``jwks``, not expired (30 s leeway), ``aud`` equal to
    ``audience``, then ``user`` / ``type`` / ``authorization_details``.
    ``audience`` is required: ``/agents/jwks.json`` is one key set for every
    Touchque workspace, so without it a token Touchque signed for another
    workspace would pass. Pass your own (``client.agents.approval_audience()``,
    ``touchque:workspace:<id>``), or use ``client.agents.verify_approval_token``,
    which fills it in. Does NOT make it single-use
    (``client.agents.redeem_approval`` does). Needs ``cryptography``."""
    if not isinstance(audience, str) or not audience:
        raise TouchQueApprovalMismatchError("audience is required: your workspace's touchque:workspace:<id> (client.agents.approval_audience())")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    decoded = decode_approval_token(token)
    header, claims = decoded['header'], decoded['claims']
    if header.get('typ') != 'touchque-approval+jwt' or header.get('alg') != 'ES256':
        raise TouchQueApprovalMismatchError('not an approval token (typ/alg)')
    jwk = next((k for k in jwks.get('keys', []) if k.get('kid') == header.get('kid') and k.get('kty') == 'EC' and k.get('crv') == 'P-256'), None)
    if not jwk:
        raise TouchQueApprovalMismatchError('signed by an unknown key')
    h, p, s = token.split('.')
    try:
        sig = _b64(s)
    except ValueError:  # not base64url (e.g. non-ASCII): a signature that does not verify
        sig = b''
    if len(sig) != 64:
        raise TouchQueApprovalMismatchError('the signature does not verify')
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64(jwk['x']), 'big'), int.from_bytes(_b64(jwk['y']), 'big'), ec.SECP256R1()).public_key()
    try:
        key.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), f'{h}.{p}'.encode('ascii'), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise TouchQueApprovalMismatchError('the signature does not verify') from exc
    current = time.time() if now is None else now
    if not isinstance(claims.get('exp'), (int, float)) or claims['exp'] + 30 < current:
        raise TouchQueApprovalMismatchError('the approval token expired')
    if not isinstance(claims.get('aud'), str) or not claims.get('aud'):
        raise TouchQueApprovalMismatchError('the approval token names no workspace')
    if claims['aud'] != audience:
        raise TouchQueApprovalMismatchError('the approval token is for another workspace')
    assert_approval_matches(claims, **expect)
    return claims
