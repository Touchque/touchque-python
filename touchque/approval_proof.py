"""Verifies the device-signed proof of an approval ("what you see is what you sign").

When the user's phone holds a hardware key (Secure Enclave / Android Keystore),
every approval is signed by it over the request id, the action type, the
number-match code and a digest of the transaction details the user was shown.
The proof arrives in the SUCCESS webhook (``approvalProof``) and in
``login.status(id)['approvalProof']``. Verifying it does not require trusting
TouchQue: it proves the enrolled phone signed exactly these details.

Needs the optional ``cryptography`` package:
``pip install "touchque-authenticator[proof]"``.
"""
import base64
import binascii
from typing import Any, Mapping, Optional

from .steps import LoginDetails, details_digest

__all__ = ['verify_approval_proof', 'details_digest']

_MESSAGE_PREFIX = 'touchque-approve:v2'


def _load_crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            'verify_approval_proof needs the "cryptography" package: '
            'pip install "touchque-authenticator[proof]"'
        ) from exc
    return InvalidSignature, hashes, ec


def verify_approval_proof(
    proof: Optional[Mapping[str, Any]],
    *,
    request_id: str,
    type: str,
    details: Optional[LoginDetails] = None,
    challenge_code: Optional[str] = None,
    expected_public_key: Optional[str] = None,
    allow_unpinned_key: bool = False,
) -> bool:
    """Returns True only if ``proof`` was signed by the device key over exactly
    the request, action type, challenge code and details you expect.

    :param proof: the ``approvalProof`` object from the webhook / status.
    :param request_id: the request id ``login.request()`` returned.
    :param type: the action type you sent (e.g. ``'WITHDRAW'``).
    :param details: the details you sent, exactly as you sent them (dict or
        list of ``{label, value}``); ``None`` when you sent none.
    :param challenge_code: the number-match code ``login.request()`` returned,
        when number matching was used.
    :param expected_public_key: pin the device — the base64 public key you
        stored for this user (e.g. ``proof['publicKey']`` of their first
        verified approval). A proof from any other key is rejected. Required
        unless ``allow_unpinned_key`` is set.
    :param allow_unpinned_key: accept whatever key the proof carries. Without a
        pinned key the proof only shows that *some* key signed these details.
        Only for trust-on-first-use: store ``proof['publicKey']`` after this
        first check and pin it from then on.

    Fails closed (no pin and no ``allow_unpinned_key`` -> False) and never
    raises for malformed input; it returns False.
    """
    InvalidSignature, hashes, ec = _load_crypto()
    try:
        if not isinstance(proof, Mapping):
            return False
        if proof.get('version') != 'v2' or proof.get('algorithm') != 'ECDSA-P256-SHA256':
            return False
        public_key_b64 = proof.get('publicKey')
        message = proof.get('message')
        signature_b64 = proof.get('signature')
        if not all(isinstance(v, str) for v in (public_key_b64, message, signature_b64)):
            return False
        if expected_public_key:
            if public_key_b64 != expected_public_key:
                return False
        elif allow_unpinned_key is not True:
            return False

        expected_message = '\n'.join([
            _MESSAGE_PREFIX,
            str(request_id),
            str(type),
            challenge_code if challenge_code is not None else '',
            details_digest(details),
        ])
        if message != expected_message:
            return False

        raw = base64.b64decode(public_key_b64, validate=True)
        if len(raw) != 65 or raw[0] != 0x04:
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        signature = base64.b64decode(signature_b64, validate=True)
        key.verify(signature, message.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False
