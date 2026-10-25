"""Validation of vote deposit transactions (jsonParsed getTransaction results).

Handles legacy, v0 and v1 shapes: accountKeys as objects ({"pubkey", "signer", ...}) or as strings
(signers then come from message.header.numRequiredSignatures), instructions parsed by the RPC or raw
(programId / programIdIndex + base58 data).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import base58

from ..constants import COMPUTE_BUDGET_PROGRAM, EXTRA_ALLOWED_PROGRAMS, MEMO_V1, MEMO_V2, SYSTEM_PROGRAM

ALLOWED_TOP_LEVEL = frozenset({SYSTEM_PROGRAM, COMPUTE_BUDGET_PROGRAM, MEMO_V1, MEMO_V2}) | EXTRA_ALLOWED_PROGRAMS
_TRANSFER_OPS = ("transfer", "transferWithSeed")
_RAW_SYSTEM_OPS = {2: "transfer", 4: "advanceNonce"}  # bincode u32 discriminators we decode
_U64_MAX = 2**64 - 1


@dataclass
class DepositCheck:
    ok: bool
    reason: str                      # reason code; "" when ok
    signature: str
    slot: int
    block_time: int | None
    sender: str | None               # source of the single top-level transfer into deposit (None if unknown)
    lamports: int                    # lamports received by deposit in that transfer (0 if unknown)
    fee_payer: str | None


class _Unparsed(Exception):
    pass


@dataclass(frozen=True)
class _Ix:
    program_id: str
    op: str | None = None            # System instruction type; None for other programs
    source: str | None = None
    destination: str | None = None
    lamports: int = 0


@dataclass
class _Tx:
    err: Any
    fee_payer: str
    signers: set[str]
    top: list[_Ix]
    inner: list[_Ix]


# ---- small validators ----------------------------------------------------------------------

def _is_int(v: Any) -> bool:
    return type(v) is int


def _pubkey(v: Any) -> str:
    if not isinstance(v, str) or not 32 <= len(v) <= 44:
        raise _Unparsed
    try:
        if len(base58.b58decode(v)) != 32:
            raise _Unparsed
    except ValueError:
        raise _Unparsed from None
    return v


def _dict(v: Any) -> dict:
    if not isinstance(v, dict):
        raise _Unparsed
    return v


def _list(v: Any) -> list:
    if not isinstance(v, list):
        raise _Unparsed
    return v


# ---- shape normalisation -------------------------------------------------------------------

def _loaded_addresses(meta: dict) -> list[str]:
    loaded = meta.get("loadedAddresses")
    if not isinstance(loaded, dict):
        return []
    return [_pubkey(k) for part in ("writable", "readonly") for k in _list(loaded.get(part, []))]


def _account_keys(msg: dict, meta: dict) -> tuple[list[str], set[str] | None]:
    """(all account keys in index order, signer set or None when it cannot be known)."""
    raw = _list(msg.get("accountKeys"))
    if not raw:
        raise _Unparsed
    if all(isinstance(k, dict) for k in raw):
        keys = [_pubkey(k.get("pubkey")) for k in raw]
        if not all(isinstance(k.get("signer"), bool) for k in raw):
            return keys, None
        return keys, {key for key, k in zip(keys, raw) if k["signer"]}
    if all(isinstance(k, str) for k in raw):
        keys = [_pubkey(k) for k in raw]
        header = msg.get("header")
        n = header.get("numRequiredSignatures") if isinstance(header, dict) else None
        signers = set(keys[:n]) if _is_int(n) and 0 < n <= len(keys) else None
        return keys + _loaded_addresses(meta), signers
    raise _Unparsed


def _key_at(keys: list[str], ref: Any) -> str:
    if isinstance(ref, str):
        return _pubkey(ref)
    if _is_int(ref) and 0 <= ref < len(keys):
        return keys[ref]
    raise _Unparsed


def _program_id(raw: dict, keys: list[str]) -> str:
    if "programId" in raw:
        return _pubkey(raw["programId"])
    return _key_at(keys, raw.get("programIdIndex"))


def _lamports(v: Any) -> int:
    if not _is_int(v) or not 0 <= v <= _U64_MAX:
        raise _Unparsed
    return v


def _system_parsed(parsed: Any) -> _Ix:
    parsed = _dict(parsed)
    op, info = parsed.get("type"), _dict(parsed.get("info"))
    if not isinstance(op, str):
        raise _Unparsed
    if op not in _TRANSFER_OPS:
        return _Ix(SYSTEM_PROGRAM, op)
    return _Ix(SYSTEM_PROGRAM, op, _pubkey(info.get("source")), _pubkey(info.get("destination")),
               _lamports(info.get("lamports")))


def _system_raw(raw: dict, keys: list[str]) -> _Ix:
    data = raw.get("data")
    if not isinstance(data, str):
        raise _Unparsed
    try:
        blob = base58.b58decode(data)
    except ValueError:
        raise _Unparsed from None
    if len(blob) < 4:
        raise _Unparsed
    op = _RAW_SYSTEM_OPS.get(int.from_bytes(blob[:4], "little"), f"raw:{blob[:4].hex()}")
    if op != "transfer":
        return _Ix(SYSTEM_PROGRAM, op)
    accounts = _list(raw.get("accounts"))
    if len(blob) != 12 or len(accounts) < 2:
        raise _Unparsed
    return _Ix(SYSTEM_PROGRAM, op, _key_at(keys, accounts[0]), _key_at(keys, accounts[1]),
               int.from_bytes(blob[4:12], "little"))


def _ix(raw: Any, keys: list[str]) -> _Ix:
    raw = _dict(raw)
    pid = _program_id(raw, keys)
    if pid != SYSTEM_PROGRAM:
        return _Ix(pid)
    return _system_parsed(raw["parsed"]) if "parsed" in raw else _system_raw(raw, keys)


def _inner_groups(meta: dict) -> list[tuple[int, list]]:
    groups = []
    for g in _list(meta.get("innerInstructions")):
        g = _dict(g)
        if not _is_int(g.get("index")):
            raise _Unparsed
        groups.append((g["index"], _list(g.get("instructions"))))
    return groups


def _message(tx: Any) -> tuple[dict, dict]:
    tx = _dict(tx)
    meta = _dict(tx.get("meta"))
    msg = _dict(_dict(tx.get("transaction")).get("message"))
    return msg, meta


def _parse(tx: Any) -> _Tx:
    msg, meta = _message(tx)
    version, slot, block_time = tx.get("version"), tx.get("slot"), tx.get("blockTime")
    if not (version is None or version == "legacy" or (_is_int(version) and version in (0, 1))):
        raise _Unparsed
    if not (_is_int(slot) and slot >= 0) or not (block_time is None or _is_int(block_time)):
        raise _Unparsed
    if "err" not in meta:
        raise _Unparsed
    keys, signers = _account_keys(msg, meta)
    if signers is None:
        raise _Unparsed
    top = [_ix(r, keys) for r in _list(msg.get("instructions"))]
    inner = [_ix(r, keys) for _, group in _inner_groups(meta) for r in group]
    return _Tx(meta["err"], keys[0], signers, top, inner)


def _identity(tx: Any) -> tuple[str, int, int | None]:
    """Best-effort (signature, slot, block_time) that never raises."""
    t = tx if isinstance(tx, dict) else {}
    body = t.get("transaction")
    sigs = body.get("signatures") if isinstance(body, dict) else None
    sig = sigs[0] if isinstance(sigs, list) and sigs and isinstance(sigs[0], str) else ""
    slot, block_time = t.get("slot"), t.get("blockTime")
    return sig, slot if _is_int(slot) else 0, block_time if _is_int(block_time) else None


def _reason(p: _Tx, deposit: str, into: list[_Ix], slot: int, open_slot: int | None,
            close_slot: int | None) -> str:
    if p.err is not None:
        return "failed_tx"
    if any(ix.op == "advanceNonce" for ix in p.top + p.inner):
        return "nonce"
    if any(ix.program_id not in ALLOWED_TOP_LEVEL for ix in p.top):
        return "shape"
    if p.inner:
        return "inner"
    if len(into) != 1 or sum(ix.program_id == SYSTEM_PROGRAM for ix in p.top) != 1:
        return "count"
    if into[0].source == deposit:
        return "self"
    if into[0].source not in p.signers:
        return "not_signer"
    if open_slot is not None and slot < open_slot:
        return "before_open"
    if close_slot is not None and slot > close_slot:
        return "after_close"
    return ""


def _lenient_keys(msg: dict, meta: dict) -> list[str]:
    try:
        return _account_keys(msg, meta)[0]
    except _Unparsed:
        return []  # parsed instructions carry their own pubkeys


# ---- public API ----------------------------------------------------------------------------

def check_deposit(tx: dict, deposit: str, open_slot: int | None, close_slot: int | None) -> DepositCheck:
    sig, slot, block_time = _identity(tx)
    try:
        if not sig:
            raise _Unparsed
        p = _parse(tx)
    except _Unparsed:
        return DepositCheck(False, "unparsed", sig, slot, block_time, None, 0, None)
    into = [ix for ix in p.top if ix.op == "transfer" and ix.destination == deposit]
    sender, lamports = (into[0].source, into[0].lamports) if len(into) == 1 else (None, 0)
    reason = _reason(p, deposit, into, slot, open_slot, close_slot)
    return DepositCheck(reason == "", reason, sig, slot, block_time, sender, lamports, p.fee_payer)


def incoming_transfers(tx: dict, deposit: str) -> list[tuple[str, int]]:
    """Every (source, lamports) System transfer into deposit, top-level and inner, in execution order.

    Only successful transactions moved funds, so anything else yields []. Malformed instructions are
    skipped (never guessed), and self-transfers or zero amounts are left out.
    """
    try:
        msg, meta = _message(tx)
        top = _list(msg.get("instructions"))
        groups = _inner_groups(meta) if meta.get("innerInstructions") is not None else []
        keys = _lenient_keys(msg, meta)
    except _Unparsed:
        return []
    if "err" not in meta or meta["err"] is not None:
        return []
    inner_by_index: dict[int, list] = {}
    for index, group in groups:
        inner_by_index.setdefault(index, []).extend(group)
    ordered: list = []
    for i, raw in enumerate(top):  # inner groups pointing at no top-level instruction are ignored
        ordered.append(raw)
        ordered.extend(inner_by_index.get(i, []))
    out: list[tuple[str, int]] = []
    for raw in ordered:
        try:
            ix = _ix(raw, keys)
        except _Unparsed:
            continue
        if (ix.op in _TRANSFER_OPS and ix.source and ix.destination == deposit and ix.source != deposit
                and ix.lamports > 0):
            out.append((ix.source, ix.lamports))
    return out
