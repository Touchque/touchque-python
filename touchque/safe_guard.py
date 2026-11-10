"""Safe Guard approvals, checked without trusting TouchQue.

The approver's phone decodes the raw Safe transaction itself and signs, with a P-256 key only
its biometrics unlock, a 105-byte approval that TouchQueSafeGuard checks on chain::

    index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)

over the SHA-256 of the 149-byte message::

    "TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) | subject (32) | expiresAt (8) | displayDigest (32)

where subject is the Safe transaction hash (EIP-712, purpose 1 ``approve``) or, for a change the
guard schedules, the governance hash (purpose 2 ``schedule``). ``verify_safe_approval`` makes the
guard's check off chain: both hashes are computed here from the raw fields, so a co-signer (or
your own server) refuses an approval of anything else, whoever relayed it.

The hashes need nothing else; ``verify_safe_approval`` needs the optional ``cryptography``
package: ``pip install "touchque-authenticator[proof]"``.
"""
import datetime
import hashlib
import re
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from .exceptions import TouchQueConfigException

__all__ = [
    'safe_tx_hash', 'safe_governance_hash', 'safe_approval_message', 'safe_display_digest', 'verify_safe_approval',
    'with_safe_approvals', 'safe_schedule_call',
]

_MAGIC = b'TQG1'
_PURPOSES = {'approve': 1, 'schedule': 2}
# The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
_MAX_APPROVAL_TTL = 86400
# OpenZeppelin P256 (the guard) refuses s above N/2.
_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
_MAX_UINT256 = (1 << 256) - 1
_MAX_UINT64 = (1 << 64) - 1
_ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
_ADDRESS = re.compile(r'^0x[0-9a-fA-F]{40}$')
_HEX = re.compile(r'^0x(?:[0-9a-fA-F]{2})*$')
_APPROVAL = re.compile(r'^(?:0x)?[0-9a-fA-F]{210}$')
_KEY = re.compile(r'^[0-9a-fA-F]{128}$')

# ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) ──
_RC = [int(h, 16) for h in (
    '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000', '000000000000808b', '0000000080000001',
    '8000000080008081', '8000000000008009', '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
    '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003', '8000000000008002', '8000000000000080',
    '000000000000800a', '800000008000000a', '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
)]
# Rotation of lane x + 5y.
_ROT = (0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
_MASK = (1 << 64) - 1


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a: List[int]) -> List[int]:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x + 5 * y])
        a = [b[i] ^ (~b[i - i % 5 + (i + 1) % 5] & b[i - i % 5 + (i + 2) % 5]) for i in range(25)]
        a[0] ^= rc
    return a


def _keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data) + bytearray(rate - len(data) % rate)
    padded[len(data)] ^= 0x01
    padded[-1] ^= 0x80
    a = [0] * 25
    for off in range(0, len(padded), rate):
        for k in range(rate // 8):
            a[k] ^= int.from_bytes(padded[off + 8 * k:off + 8 * k + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[k].to_bytes(8, 'little') for k in range(4))


_DOMAIN_TYPEHASH = _keccak256(b'EIP712Domain(uint256 chainId,address verifyingContract)')
_SAFE_TX_TYPEHASH = _keccak256(
    b'SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,'
    b'address gasToken,address refundReceiver,uint256 nonce)')
_GOVERNANCE_TYPEHASH = _keccak256(b'TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)')
_SCHEDULE_SELECTOR = _keccak256(b'schedule(address,bytes32,bytes)')[:4]


# ── Field parsing: the partner's own data, so a wrong field raises ──
def _uint(value: Any, field: str, top: int = _MAX_UINT256) -> int:
    v = None
    if isinstance(value, int) and not isinstance(value, bool):
        v = value
    elif isinstance(value, str) and re.match(r'^(0|[1-9][0-9]*)$', value):
        v = int(value)
    if v is None or v < 0 or v > top:
        raise TouchQueConfigException(f'safe_guard: {field} must be a non-negative integer (a decimal string for large values).')
    return v


def _address(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not _ADDRESS.match(value):
        raise TouchQueConfigException(f'safe_guard: {field} must be an address (0x and 40 hex characters).')
    return bytes.fromhex(value[2:])


def _hex(value: Any, field: str, size: Optional[int] = None) -> bytes:
    if not isinstance(value, str) or not _HEX.match(value) or (size is not None and len(value) != 2 + 2 * size):
        raise TouchQueConfigException(f'safe_guard: {field} must be 0x-prefixed hex' + (f' of {size} bytes.' if size is not None else '.'))
    return bytes.fromhex(value[2:])


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith('0x') else s


def _word(v: int) -> bytes:
    return v.to_bytes(32, 'big')


def _pad(b: bytes) -> bytes:
    return bytes(32 - len(b)) + b


def _target(target: Mapping[str, Any]) -> Dict[str, Any]:
    tx = target.get('tx') if isinstance(target, Mapping) else None
    if not isinstance(tx, Mapping):
        raise TouchQueConfigException('safe_guard: pass {"chainId", "safe", "guard", "tx": {"to", "value", "data", "operation", ..., "nonce"}}.')
    operation = tx.get('operation', 0)
    if operation not in (0, 1) or isinstance(operation, bool):
        raise TouchQueConfigException('safe_guard: tx.operation must be 0 (call) or 1 (delegatecall).')
    return {
        'chainId': _uint(target.get('chainId'), 'chainId', _MAX_UINT64),
        'safe': _address(target.get('safe'), 'safe'),
        'guard': _address(target.get('guard'), 'guard'),
        'to': _address(tx.get('to'), 'tx.to'),
        'value': _uint(tx.get('value', 0), 'tx.value'),
        'data': _hex(tx.get('data', '0x'), 'tx.data'),
        'operation': operation,
        'safeTxGas': _uint(tx.get('safeTxGas', 0), 'tx.safeTxGas'),
        'baseGas': _uint(tx.get('baseGas', 0), 'tx.baseGas'),
        'gasPrice': _uint(tx.get('gasPrice', 0), 'tx.gasPrice'),
        'gasToken': _address(tx.get('gasToken', _ZERO_ADDRESS), 'tx.gasToken'),
        'refundReceiver': _address(tx.get('refundReceiver', _ZERO_ADDRESS), 'tx.refundReceiver'),
        'nonce': _uint(tx.get('nonce'), 'tx.nonce'),
    }


def safe_tx_hash(target: Mapping[str, Any]) -> str:
    """The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and an ordinary approval covers."""
    t = _target(target)
    domain = _keccak256(_DOMAIN_TYPEHASH + _word(t['chainId']) + _pad(t['safe']))
    struct = _keccak256(
        _SAFE_TX_TYPEHASH + _pad(t['to']) + _word(t['value']) + _keccak256(t['data']) + _word(t['operation'])
        + _word(t['safeTxGas']) + _word(t['baseGas']) + _word(t['gasPrice']) + _pad(t['gasToken']) + _pad(t['refundReceiver'])
        + _word(t['nonce']))
    return '0x' + _keccak256(b'\x19\x01' + domain + struct).hex()


def safe_governance_hash(target: Mapping[str, Any]) -> str:
    """What the guard schedules a governance change under: the change itself, without the nonce or gas fields."""
    t = _target(target)
    return '0x' + _keccak256(
        _GOVERNANCE_TYPEHASH + _word(t['chainId']) + _pad(t['safe']) + _pad(t['to']) + _word(t['value'])
        + _keccak256(t['data']) + _word(t['operation'])).hex()


def safe_approval_message(purpose: str, chain_id: Union[int, str], guard: str, safe: str, subject: str,
                          expires_at: Union[int, str], display_digest: str) -> str:
    """The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex."""
    if purpose not in _PURPOSES:
        raise TouchQueConfigException("safe_guard: purpose is 'approve' or 'schedule'.")
    return '0x' + (
        _MAGIC + bytes([_PURPOSES[purpose]]) + _word(_uint(chain_id, 'chainId', _MAX_UINT64)) + _address(guard, 'guard')
        + _address(safe, 'safe') + _hex(subject, 'subject', 32) + _uint(expires_at, 'expiresAt', _MAX_UINT64).to_bytes(8, 'big')
        + _hex(display_digest, 'displayDigest', 32)).hex()


def safe_display_digest(rows: Iterable[Mapping[str, str]]) -> str:
    """SHA-256 of the rows as "label\\x1Fvalue" joined by "\\x1E" (UTF-8), as 0x hex: the digest an approval carries."""
    canonical = '\x1e'.join(f"{r['label']}\x1f{r['value']}" for r in rows)
    return '0x' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _public_key(key: Union[str, Mapping[str, str]]):
    if isinstance(key, Mapping):
        xy = _strip0x(str(key.get('x', ''))) + _strip0x(str(key.get('y', '')))
    else:
        xy = _strip0x(str(key))
    if not _KEY.match(xy):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise TouchQueConfigException('Safe Guard approvals need the cryptography package: pip install "touchque-authenticator[proof]"') from e
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + bytes.fromhex(xy))
    except ValueError:
        return None


def _seconds(now: Union[None, int, float, datetime.datetime]) -> int:
    if now is None:
        return int(time.time())
    if isinstance(now, datetime.datetime):
        return int(now.timestamp())
    return int(now)


def verify_safe_approval(target: Mapping[str, Any], approval: str, public_key: Union[str, Mapping[str, str]], *,
                         purpose: Optional[str] = None, approver_index: Optional[int] = None,
                         display_digest: Optional[str] = None, rows: Optional[Iterable[Mapping[str, str]]] = None,
                         now: Union[None, int, float, datetime.datetime] = None) -> Dict[str, Any]:
    """Checks a phone's Safe Guard approval the way TouchQueSafeGuard does, without trusting the server that relayed it.

    The Safe and governance hashes come from ``target`` (``{"chainId", "safe", "guard", "tx"}``),
    the key from the guard's approver list on chain (``x || y``, 128 hex characters, or
    ``{"x", "y"}``). ``purpose`` (``approve`` or ``schedule``): the one you expect; without it,
    only ``approve`` (this exact transaction, to execute) is accepted, so name ``schedule`` to
    check an approval that schedules a governance change. ``approver_index``: the approval
    must name it. ``display_digest`` or ``rows``: from your own decoding, the rows the phone must
    have shown. ``now``: a datetime or Unix seconds.

    Returns ``{"valid", "reason", "purpose", "approverIndex", "expiresAt", "displayDigest",
    "safeTxHash", "governanceHash"}``; ``reason`` is ``None`` when valid, else one of
    ``approval_malformed``, ``public_key_invalid``, ``approver_index_mismatch``,
    ``approval_expired``, ``rows_differ``, ``high_s``, ``signature_invalid``. Raises only when
    ``target`` is not a Safe transaction::

        status = tq.safe_guard.status(request_id)
        check = verify_safe_approval(my_tx, status['safeTx']['approval'], approver_key_from_chain, approver_index=0)
        if not check['valid']:
            raise RuntimeError(f"approval refused: {check['reason']}")
    """
    t = _target(target)
    hashes = {'safeTxHash': safe_tx_hash(target), 'governanceHash': safe_governance_hash(target)}
    parsed: Dict[str, Any] = {'approverIndex': None, 'expiresAt': None, 'displayDigest': None}

    def refuse(reason: str) -> Dict[str, Any]:
        return {'valid': False, 'reason': reason, 'purpose': None, **parsed, **hashes}

    if not isinstance(approval, str) or not _APPROVAL.match(approval):
        return refuse('approval_malformed')
    b = bytes.fromhex(_strip0x(approval))
    expires_at = int.from_bytes(b[1:9], 'big')
    parsed = {'approverIndex': b[0], 'expiresAt': expires_at, 'displayDigest': '0x' + b[9:41].hex()}
    key = _public_key(public_key)
    if key is None:
        return refuse('public_key_invalid')
    if approver_index is not None and approver_index != b[0]:
        return refuse('approver_index_mismatch')
    seconds = _seconds(now)
    if expires_at < seconds or expires_at > seconds + _MAX_APPROVAL_TTL:
        return refuse('approval_expired')
    expected = display_digest if display_digest is not None else (safe_display_digest(rows) if rows is not None else None)
    if expected is not None and '0x' + _strip0x(expected.lower()) != parsed['displayDigest']:
        return refuse('rows_differ')
    s = int.from_bytes(b[73:105], 'big')
    if s > _HALF_N:
        return refuse('high_s')

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    signature = encode_dss_signature(int.from_bytes(b[41:73], 'big'), s)
    # Never both: a schedule approval (no nonce, no gas fields) must not pass as one to execute.
    p = purpose or 'approve'
    message = safe_approval_message(
        p, t['chainId'], '0x' + t['guard'].hex(), '0x' + t['safe'].hex(),
        hashes['safeTxHash'] if p == 'approve' else hashes['governanceHash'], expires_at, parsed['displayDigest'])
    try:
        key.verify(signature, bytes.fromhex(message[2:]), ec.ECDSA(crypto_hashes.SHA256()))
    except InvalidSignature:
        return refuse('signature_invalid')
    return {'valid': True, 'reason': None, 'purpose': p, **parsed, **hashes}


def _approvals(approvals: Iterable[str]) -> List[bytes]:
    items = list(approvals)
    if not 1 <= len(items) <= 255:
        raise TouchQueConfigException('safe_guard: pass 1 to 255 approvals.')
    out = [_hex(a if isinstance(a, str) and a.startswith('0x') else f'0x{a}', f'approvals[{i}]', 105) for i, a in enumerate(items)]
    return sorted(out, key=lambda a: a[0])


def with_safe_approvals(owner_signatures: str, approvals: Iterable[str]) -> str:
    """The owners' Safe signatures with the approvals appended (approvals by index | count | "TQG1"):
    the ``signatures`` argument of ``execTransaction`` for an ordinary transaction."""
    items = _approvals(approvals)
    return '0x' + (_hex(owner_signatures, 'ownerSignatures') + b''.join(items) + bytes([len(items)]) + _MAGIC).hex()


def safe_schedule_call(safe: str, governance_hash: str, approvals: Iterable[str]) -> str:
    """The call data of ``guard.schedule(safe, governanceHash, approvals)``, which starts a governance change's waiting time."""
    joined = b''.join(_approvals(approvals))
    return '0x' + (
        _SCHEDULE_SELECTOR + _pad(_address(safe, 'safe')) + _hex(governance_hash, 'governanceHash', 32) + _word(96)
        + _word(len(joined)) + joined + bytes(-len(joined) % 32)).hex()
