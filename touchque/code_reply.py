"""A code the person types back on the phone (``login.request(reply=...)``).

A sign-in code another service sent them (a text message, WhatsApp, e-mail). Each request gets
a one-time P-256 key pair; its public key goes with the request, the phone encrypts what was
typed to it, and only you can open it: TouchQue stores and hands back nothing but the
ciphertext (``login.status(request_id)['reply']['ct']``).

ECDH P-256, HKDF-SHA256 (salt: the request id, info ``touchque-code-reply-v1``), AES-256-GCM
(additional data ``touchque-code-reply:<request id>``), as
``v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>``, base64url.

Needs the optional ``cryptography`` package: ``pip install "touchque-authenticator[proof]"``.
"""
import base64
import re
from typing import Dict, Optional

from .exceptions import TouchQueConfigException

_INFO = b'touchque-code-reply-v1'
_CT_RE = re.compile(r'^v1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$')
_CODE_RE = re.compile(r'^[A-Za-z0-9 -]{4,20}$')


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise TouchQueConfigException('Code replies need the cryptography package: pip install "touchque-authenticator[proof]"') from e
    return hashes, serialization, ec, AESGCM, HKDF


def new_code_reply_key() -> Dict[str, str]:
    """A one-time key pair for one request: send ``public_key`` as ``reply['key']``, keep ``private_key``.

    ``public_key``: the uncompressed P-256 point (65 bytes), base64url. ``private_key``: PKCS#8 DER,
    base64url; keep it server-side, for this one request.
    """
    hashes, serialization, ec, _, _ = _crypto()
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return {'public_key': _b64(public), 'private_key': _b64(private)}


def open_code_reply(private_key: str, request_id: str, ct: str) -> Optional[str]:
    """The code the person typed, or ``None`` when ``ct`` does not open with this key for this request."""
    hashes, serialization, ec, AESGCM, HKDF = _crypto()
    try:
        m = _CT_RE.match(str(ct or ''))
        if not m:
            return None
        epk, box = _unb64(m.group(1)), _unb64(m.group(2))
        if len(epk) != 65 or epk[0] != 4 or len(box) < 12 + 16 + 1:
            return None
        priv = serialization.load_der_private_key(_unb64(private_key), password=None)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk)
        shared = priv.exchange(ec.ECDH(), peer)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=str(request_id).encode('utf-8'), info=_INFO).derive(shared)
        aad = ('touchque-code-reply:%s' % request_id).encode('utf-8')
        code = AESGCM(key).decrypt(box[:12], box[12:], aad).decode('utf-8').strip()
        return code if _CODE_RE.match(code) else None
    except Exception:  # noqa: BLE001 - anything wrong is "does not open"
        return None
