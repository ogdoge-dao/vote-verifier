#!/usr/bin/env python3
"""Standalone verifier for an OGDOGE DAO audit package.

    python tools/verify.py <audit.zip> [--rpc URL [--notary ADDRESS]]

Recomputes the content hash, the hash chain, every snapshot's CSV hash and merkle root, power and the
tally from the package files alone (independent of the server code), and prints PASS/FAIL per check.
With --rpc it also re-fetches every vote transaction and re-runs the deposit validator, and confirms that
every anchor marked as sent is on Solana with the same memo, paid by one wallet (--notary pins which).
Exit code 0 when every check passes. Needs Python 3.10+, base58 and solders; nothing else from the server.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from fractions import Fraction
from pathlib import Path
from typing import Any

import base58
from solders.pubkey import Pubkey

GENESIS = "0" * 64
ANCHOR = "OGDOGE-DAO|v1"
MEMO_PROGRAMS = {"Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"}
# Tally keys added with rules.min_voters; tallies anchored before that have none of them.
MIN_VOTERS_KEYS = ("quorum_power_reached", "min_voters", "min_voters_reached")
INT_COLS = {"option", "created_at", "lamports", "slot", "block_time", "valid", "superseded", "added_at", "id"}


class Fail(Exception):
    pass


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- package -------------------------------------------------------------------------------

def _cell(key: str, value: str) -> Any:
    if value == "":
        return None
    return int(value) if key in INT_COLS else value


def _read_csv(text: str) -> list[dict]:
    return [{k: _cell(k, v) for k, v in row.items()} for row in csv.DictReader(io.StringIO(text))]


def _balances(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        owner, amount = line.split(",")
        if owner in out:
            raise Fail(f"duplicate owner {owner}")
        out[owner] = int(amount)
    return out


class Package:
    def __init__(self, path: str) -> None:
        with zipfile.ZipFile(path) as z:
            read = lambda name: z.read(name).decode()  # noqa: E731
            self.proposal: dict = json.loads(read("proposal.json"))
            self.tally: dict = json.loads(read("tally.json"))
            self.exclusions = _read_csv(read("exclusions.csv"))
            names = set(z.namelist())
            # Published proposals carry the list frozen at publish; older packages only the global one.
            self.frozen_exclusions = (_read_csv(read("proposal_exclusions.csv"))
                                      if "proposal_exclusions.csv" in names else None)
            self.sessions = _read_csv(read("sessions.csv"))
            self.deposits = _read_csv(read("deposits.csv"))
            self.votes = _read_csv(read("votes.csv"))
            self.anchors = _read_csv(read("anchors.csv"))
            self.snapshots: list[dict] = json.loads(read("snapshots.json"))
            self.csv_text = {s["id"]: read(f"snapshots/{s['id']}.csv") for s in self.snapshots}
            self.hashlog = [json.loads(line) for line in read("hashlog.jsonl").splitlines() if line.strip()]
        self.balances = {sid: _balances(text) for sid, text in self.csv_text.items()}

    def logged(self, kind: str) -> list[dict]:
        return [e["payload"] for e in self.hashlog if e["kind"] == kind]


# ---- recomputation -------------------------------------------------------------------------

def merkle_root(by_owner: dict[str, int]) -> str:
    level = [hashlib.sha256(b"\x00" + base58.b58decode(o) + by_owner[o].to_bytes(8, "little")).digest()
             for o in sorted(by_owner) if by_owner[o] > 0]
    if not level:
        return sha256_hex(b"")
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def content_hash(p: dict) -> str:
    keys = ("id", "title", "summary", "body", "kind", "founder", "options", "rules")
    return sha256_hex(canonical_json({k: p[k] for k in keys}).encode())


def counted_snapshots(pkg: Package) -> list[int]:
    p = pkg.proposal
    if p.get("elig_snapshot_id") is None:
        return []
    later = [s["id"] for s in pkg.snapshots if s["proposal_id"] == p["id"] and s["kind"] in ("check", "final")
             and p["open_slot"] is not None and s["slot"] >= p["open_slot"]]
    return [p["elig_snapshot_id"], *later]


def wallet_power(pkg: Package, wallet: str) -> int:
    ids = counted_snapshots(pkg)
    return min((pkg.balances[i].get(wallet, 0) for i in ids), default=0)


def current_votes(pkg: Package) -> dict[str, dict]:
    """wallet -> latest vote (highest slot, then signature)."""
    latest: dict[str, dict] = {}
    for v in pkg.votes:
        cur = latest.get(v["wallet"])
        if cur is None or (v["slot"], v["signature"]) > (cur["slot"], cur["signature"]):
            latest[v["wallet"]] = v
    return latest


def in_window(p: dict, slot: int) -> bool:
    if p["open_slot"] is None or slot < p["open_slot"]:
        return False
    return p["close_slot"] is None or slot <= p["close_slot"]


def _on_curve(owner: str) -> bool:
    try:
        return Pubkey.from_string(owner).is_on_curve()
    except ValueError:
        return False


def _tally(pkg: Package) -> tuple[dict, int]:
    """(tally, counted wallets including those whose power fell to 0)."""
    p = pkg.proposal
    names, rules = p["options"], p["rules"]
    excluded = {e["address"] for e in excluded_rows(pkg)}
    elig = pkg.balances.get(p["elig_snapshot_id"], {})
    options = [{"name": n, "power": 0, "wallets": 0} for n in names]
    voters, counted, lost = 0, 0, 0
    for wallet, v in sorted(current_votes(pkg).items()):
        if wallet in excluded or not 0 <= v["option"] < len(names) or not in_window(p, v["slot"]):
            continue
        w = wallet_power(pkg, wallet)
        options[v["option"]]["power"] += w
        options[v["option"]]["wallets"] += 1
        counted += 1
        voters += w > 0
        lost += elig.get(wallet, 0) - w
    cast = sum(o["power"] for o in options)
    votable = sum(a for o, a in elig.items() if o not in excluded and _on_curve(o))
    q = Fraction(str(float(rules["quorum_pct"])))
    needed = -((-votable * q.numerator) // (q.denominator * 100))
    min_voters = rules.get("min_voters", 0)
    if type(min_voters) is not int or min_voters < 0:
        raise Fail(f"rules.min_voters is not a whole number: {min_voters!r}")
    power_ok, voters_ok = cast >= needed, voters >= min_voters
    final = any(s["kind"] == "final" and s["proposal_id"] == p["id"] for s in pkg.snapshots)
    p0, p1 = options[0]["power"], options[1]["power"]
    rule_ok = (p0 > 0 and 3 * p0 >= 2 * (p0 + p1)) if rules["pass_rule"] == "two_thirds" else p0 > p1
    return {"proposal_id": p["id"], "options": options, "cast": cast, "voters": voters, "votable_supply": votable,
            "quorum_pct": float(rules["quorum_pct"]), "quorum_needed": needed,
            "quorum_reached": power_ok and voters_ok, "quorum_power_reached": power_ok, "min_voters": min_voters,
            "min_voters_reached": voters_ok, "lost": lost, "final": final, "pass_rule": rules["pass_rule"],
            "passed": (power_ok and voters_ok and rule_ok) if final else None}, counted


def recompute_tally(pkg: Package) -> dict:
    return _tally(pkg)[0]


def legacy_rules(pkg: Package) -> bool:
    """Rules published before min_voters existed (the content hash covers rules, so this can't be faked)."""
    return "min_voters" not in pkg.proposal["rules"]


def legacy_tally(pkg: Package) -> dict:
    """The tally as servers computed it before min_voters: no new keys, every counted wallet a voter.

    Only for legacy rules: min_voters is then 0, so quorum_reached and passed are the same as now.
    """
    t, counted = _tally(pkg)
    out = {k: v for k, v in t.items() if k not in MIN_VOTERS_KEYS}
    out["voters"] = counted
    return out


# ---- checks --------------------------------------------------------------------------------

def _expect(cond: bool, detail: str) -> None:
    if not cond:
        raise Fail(detail)


def frozen_hash(pkg: Package) -> str | None:
    """Hash of the list frozen at publish, as recorded in the hash chain (proposal.json must agree).

    The hash-chained publish entry decides whether a frozen list applies: proposal.json alone is not covered
    by any hash, so blanking its exclusions_hash must not switch the verifier to the global list.
    """
    p = pkg.proposal
    pub = [e for e in pkg.logged("proposal") if e["id"] == p["id"] and e["action"] == "publish"]
    logged = pub[0].get("exclusions_hash") if pub else None
    if logged != p.get("exclusions_hash"):
        raise Fail(f"proposal.json exclusions_hash {p.get('exclusions_hash')} != publish entry {logged}")
    return logged


def excluded_rows(pkg: Package) -> list[dict]:
    """The exclusion list that applies to this proposal: the frozen copy when the proposal has one."""
    if frozen_hash(pkg) is not None:
        if pkg.frozen_exclusions is None:
            raise Fail("proposal has an exclusions_hash but the package has no proposal_exclusions.csv")
        return pkg.frozen_exclusions
    return pkg.exclusions


def exclusions_hash(rows: list[dict]) -> str:
    return sha256_hex("".join(f"{r['address']},{r['kind']}\n" for r in sorted(rows, key=lambda r: r["address"])).encode())


def check_exclusions(pkg: Package) -> str:
    p = pkg.proposal
    if frozen_hash(pkg) is None:
        return f"no frozen list (legacy package); {len(pkg.exclusions)} global exclusions used"
    rows = excluded_rows(pkg)
    h = exclusions_hash(rows)
    _expect(h == p["exclusions_hash"], f"recomputed {h} != {p['exclusions_hash']}")
    pub = [e for e in pkg.logged("proposal") if e["id"] == p["id"] and e["action"] == "publish"]
    _expect(len(pub) == 1 and pub[0].get("exclusions_hash") == h, "publish entry has a different exclusions hash")
    memo = f"{ANCHOR}|{p['id']}|exclusions|{len(rows)}|{h}"
    _expect(any(a["kind"] == "exclusions" and a["ref"] == p["id"] and a["memo"] == memo for a in pkg.anchors),
            "no exclusions anchor with this hash")
    return f"{len(rows)} addresses, hash {h[:16]}"


def check_content_hash(pkg: Package) -> str:
    h = content_hash(pkg.proposal)
    _expect(h == pkg.proposal["content_hash"], f"recomputed {h} != {pkg.proposal['content_hash']}")
    return h


def check_hash_chain(pkg: Package) -> str:
    prev = GENESIS
    for seq, e in enumerate(pkg.hashlog, start=1):
        h = sha256_hex(f"{prev}|{seq}|{e['kind']}|{canonical_json(e['payload'])}".encode())
        _expect(e["seq"] == seq and e["prev_hash"] == prev and e["hash"] == h, f"broken at seq {e['seq']}")
        prev = h
    return f"{len(pkg.hashlog)} entries, head {prev[:16]}"


def check_publish(pkg: Package) -> str:
    p = pkg.proposal
    pub = [e for e in pkg.logged("proposal") if e["id"] == p["id"] and e["action"] == "publish"]
    _expect(len(pub) == 1, f"{len(pub)} publish entries in the hash chain")
    e = pub[0]
    _expect(e["content_hash"] == p["content_hash"], "published content hash differs")
    _expect(e.get("elig_snapshot_id") == p["elig_snapshot_id"], "eligibility snapshot differs from publish entry")
    _expect(e.get("close_at") == p["close_at"] and e.get("open_at") == p["open_at"], "voting window differs")
    memo = f"{ANCHOR}|{p['id']}|publish|{p['content_hash']}"
    _expect(any(a["kind"] == "publish" and a["ref"] == p["id"] and a["memo"] == memo for a in pkg.anchors),
            "no publish anchor with this content hash")
    return p["content_hash"]


def check_snapshots(pkg: Package) -> str:
    logged = {e["id"]: e for e in pkg.logged("snapshot")}
    _expect(pkg.proposal["elig_snapshot_id"] in pkg.balances, "eligibility snapshot missing")
    for s in pkg.snapshots:
        sid, text = s["id"], pkg.csv_text[s["id"]]
        _expect(sha256_hex(text.encode()) == s["csv_sha256"], f"snapshot {sid}: CSV hash mismatch")
        _expect(merkle_root(pkg.balances[sid]) == s["merkle_root"], f"snapshot {sid}: merkle root mismatch")
        _expect(len(pkg.balances[sid]) == s["holders"], f"snapshot {sid}: holder count mismatch")
        e = logged.get(sid)
        _expect(e is not None and (e["kind"], e["slot"], e["csv_sha256"], e["merkle_root"])
                == (s["kind"], s["slot"], s["csv_sha256"], s["merkle_root"]), f"snapshot {sid}: not in hash chain")
        for a in pkg.anchors:
            if a["kind"] == s["kind"] and a["ref"] == str(sid):
                _expect(a["memo"].endswith(f"|{s['kind']}|{sid}|{s['merkle_root']}"), f"snapshot {sid}: anchor memo")
    return f"{len(pkg.snapshots)} snapshots"


def check_sessions(pkg: Package) -> str:
    logged = {e["session_id"]: e for e in pkg.logged("session_issued")}
    for s in pkg.sessions:
        e = logged.get(s["session_id"])
        _expect(e is not None and (e["kind"], e["option"], e["deposit"], e["proposal_id"])
                == (s["kind"], s["option"], s["deposit"], pkg.proposal["id"]), f"session {s['session_id']} not logged")
    return f"{len(pkg.sessions)} sessions"


def check_deposits(pkg: Package) -> str:
    logged = {e["signature"]: e for e in pkg.logged("deposit")}
    deposits = {s["session_id"]: s["deposit"] for s in pkg.sessions}
    keys = ("deposit", "sender", "lamports", "slot", "valid", "reason")
    for d in pkg.deposits:
        e = logged.get(d["signature"])
        row = {k: d[k] if k != "reason" else (d[k] or "") for k in keys}
        _expect(e is not None and {k: e[k] for k in keys} == row, f"deposit {d['signature']} differs from hash chain")
        _expect(deposits.get(d["session_id"]) == d["deposit"], f"deposit {d['signature']}: unknown session")
    return f"{len(pkg.deposits)} deposits"


def check_votes(pkg: Package) -> str:
    p = pkg.proposal
    logged = {e["signature"]: e for e in pkg.logged("vote") if e["proposal_id"] == p["id"]}
    sessions = {s["session_id"]: s for s in pkg.sessions}
    deposits = {d["signature"]: d for d in pkg.deposits}
    elig = pkg.balances.get(p["elig_snapshot_id"], {})
    latest = current_votes(pkg)
    _expect(set(logged) == {v["signature"] for v in pkg.votes}, "votes.csv and hash chain list different votes")
    for v in pkg.votes:
        sig, e = v["signature"], logged[v["signature"]]
        _expect({k: v[k] for k in e} == e, f"vote {sig} differs from hash chain")
        d, s = deposits.get(sig), sessions.get(v["session_id"])
        _expect(d is not None and d["valid"] == 1 and d["sender"] == v["wallet"], f"vote {sig}: no valid deposit")
        _expect(s is not None and s["kind"] == "vote" and s["option"] == v["option"] and s["deposit"] == d["deposit"],
                f"vote {sig}: session mismatch")
        _expect(in_window(p, v["slot"]), f"vote {sig}: outside [open_slot, close_slot]")
        _expect(elig.get(v["wallet"], 0) > 0, f"vote {sig}: wallet not in eligibility snapshot")
        _expect(v["superseded"] == int(latest[v["wallet"]]["signature"] != sig), f"vote {sig}: superseded flag")
    _expect(sum(d["valid"] == 1 for d in pkg.deposits) == len(pkg.votes), "valid deposits without a vote")
    return f"{len(pkg.votes)} votes, {len(latest)} wallets"


def check_tally(pkg: Package) -> str:
    old_package = legacy_rules(pkg) and not any(k in pkg.tally for k in MIN_VOTERS_KEYS)
    t = legacy_tally(pkg) if old_package else recompute_tally(pkg)
    diff = sorted(k for k in set(t) | set(pkg.tally) if t.get(k) != pkg.tally.get(k))
    _expect(not diff, f"tally differs in {', '.join(diff)}")
    voters = f"{t['voters']} wallets" if old_package else f"{t['voters']} of min {t['min_voters']} wallets"
    return f"cast {t['cast']} of votable {t['votable_supply']}, {voters}, passed={t['passed']}"


def _tally_memo(pkg: Package, t: dict) -> str:
    return f"{ANCHOR}|{pkg.proposal['id']}|tally|{sha256_hex(canonical_json(t).encode())}"


def check_tally_anchor(pkg: Package) -> str:
    if not pkg.tally.get("final"):
        return "not final yet"
    found = {a["memo"]: a["mode"] for a in pkg.anchors if a["kind"] == "tally" and a["ref"] == pkg.proposal["id"]}
    memo = _tally_memo(pkg, pkg.tally)
    if memo in found:
        return found[memo]
    # A proposal without rules.min_voters may have been closed (and its tally anchored) by an older server.
    if legacy_rules(pkg):
        memo = _tally_memo(pkg, legacy_tally(pkg))
        if memo in found:
            return f"{found[memo]} (tally anchored before min_voters existed)"
    raise Fail("no tally anchor matching tally.json")


CHECKS: list[tuple[str, Callable[[Package], str]]] = [
    ("content_hash", check_content_hash), ("hash_chain", check_hash_chain), ("publish", check_publish),
    ("exclusions", check_exclusions),
    ("snapshots", check_snapshots), ("sessions", check_sessions), ("deposits", check_deposits),
    ("votes", check_votes), ("tally", check_tally), ("tally_anchor", check_tally_anchor),
]


class _Refused(Exception):
    """The RPC answered the request with an error (a JSON-RPC error or HTTP 400)."""


def _rpc_call(url: str, method: str, params: list) -> Any:
    """One JSON-RPC call with the standard library; rate limits and server errors are retried."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(6):
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < 5:
                time.sleep(min(2 ** attempt, 20))
                continue
            if e.code == 400:
                raise _Refused(f"{method}: HTTP 400") from e
            raise
        if not isinstance(reply, dict):
            raise ValueError(f"{method}: malformed response")
        if reply.get("error") is not None:
            raise _Refused(f"{method}: {str(reply['error'])[:300]}")
        return reply.get("result")
    raise RuntimeError(f"{method}: the RPC kept refusing (rate limit)")


def _get_transaction(url: str, sig: str) -> dict | None:
    """Finalized jsonParsed transaction, the same request the server makes (v1 support, v0 fallback)."""
    cfg: dict[str, Any] = {"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 1}
    try:
        tx = _rpc_call(url, "getTransaction", [sig, cfg])
    except _Refused:
        tx = _rpc_call(url, "getTransaction", [sig, {**cfg, "maxSupportedTransactionVersion": 0}])
    if tx is not None and not isinstance(tx, dict):
        raise ValueError("unexpected getTransaction response")
    return tx


def _import_deposit_validator() -> Callable[..., Any]:
    """The server's deposit validator (ogdao/chain/txparse.py): next to this file in the published verifier,
    or one level up in the app checkout (tools/..)."""
    here = Path(__file__).resolve().parent
    for root in (here, here.parent):
        if (root / "ogdao" / "chain" / "txparse.py").is_file():
            sys.path.insert(0, str(root))
            break
    from ogdao.chain.txparse import check_deposit
    return check_deposit


def check_rpc(pkg: Package, url: str) -> str:
    check_deposit = _import_deposit_validator()
    p, deposits = pkg.proposal, {d["signature"]: d for d in pkg.deposits}
    for v in pkg.votes:
        tx = _get_transaction(url, v["signature"])
        _expect(tx is not None, f"vote {v['signature']}: transaction not found")
        chk = check_deposit(tx, deposits[v["signature"]]["deposit"], p["open_slot"], p["close_slot"])
        _expect(chk.ok and chk.sender == v["wallet"] and chk.slot == v["slot"],
                f"vote {v['signature']}: on-chain check failed ({chk.reason or 'sender/slot'})")
    return f"{len(pkg.votes)} transactions re-checked"


def _required_anchor_memos(pkg: Package) -> list[set[str]]:
    """Fingerprints that must be on Solana: publish, the frozen exclusion list and the final tally
    (each set holds the accepted memos for one fingerprint)."""
    p = pkg.proposal
    required = [{f"{ANCHOR}|{p['id']}|publish|{p['content_hash']}"}]
    if frozen_hash(pkg) is not None:
        rows = excluded_rows(pkg)
        required.append({f"{ANCHOR}|{p['id']}|exclusions|{len(rows)}|{exclusions_hash(rows)}"})
    if pkg.tally.get("final"):
        tally = {_tally_memo(pkg, pkg.tally)}
        if legacy_rules(pkg):
            tally.add(_tally_memo(pkg, legacy_tally(pkg)))
        required.append(tally)
    return required


def check_rpc_anchors(pkg: Package, url: str, notary: str | None = None) -> str:
    """Every anchor the package marks as sent is a finalized Solana transaction carrying exactly that memo,
    all paid by one wallet (the notary), and the publish, exclusions and final tally fingerprints are among them."""
    sent = [a for a in pkg.anchors if a["mode"] == "sent" and a["signature"]]
    payers: set[str] = set()
    on_chain: set[str] = set()
    for a in sent:
        tx = _get_transaction(url, a["signature"])
        _expect(tx is not None, f"anchor {a['kind']} {a['signature']}: transaction not found")
        _expect(not (tx.get("meta") or {}).get("err"), f"anchor {a['kind']} {a['signature']}: failed on-chain")
        msg = tx["transaction"]["message"]
        first = msg["accountKeys"][0]
        payers.add(first["pubkey"] if isinstance(first, dict) else first)
        memos = [ix.get("parsed") for ix in msg.get("instructions", []) if ix.get("programId") in MEMO_PROGRAMS]
        _expect(a["memo"] in memos, f"anchor {a['kind']} {a['signature']}: the memo on-chain is different")
        on_chain.add(a["memo"])
    missing = [sorted(accepted)[0] for accepted in _required_anchor_memos(pkg) if not accepted & on_chain]
    _expect(not missing, "not anchored on Solana: " + "; ".join(missing))
    _expect(len(payers) <= 1, f"anchors paid by {len(payers)} different wallets: {', '.join(sorted(payers))}")
    if notary:
        _expect(payers <= {notary}, f"anchors paid by {', '.join(sorted(payers))}, not by the notary {notary}")
    return f"{len(sent)} anchors found on Solana, paid by {next(iter(payers), '-')}"


def _report(name: str, fn: Callable[[], str], out: list[bool]) -> None:
    try:
        detail = fn()
        print(f"PASS {name}: {detail}")
        out.append(True)
    except Fail as e:
        print(f"FAIL {name}: {e}")
        out.append(False)
    except (KeyError, TypeError, ValueError) as e:
        print(f"FAIL {name}: malformed package ({type(e).__name__}: {e})")
        out.append(False)
    except Exception as e:  # e.g. RPC failures: never report PASS on an unexpected error
        print(f"FAIL {name}: {type(e).__name__}: {e}")
        out.append(False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("zip")
    ap.add_argument("--rpc", help="Solana RPC URL to re-check every vote and every anchor on-chain")
    ap.add_argument("--notary", help="with --rpc: the notary wallet address the anchors must be paid by")
    args = ap.parse_args(argv)
    try:
        pkg = Package(args.zip)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, Fail) as e:
        print(f"FAIL package: cannot read ({type(e).__name__}: {e})")
        return 1
    results: list[bool] = []
    for name, fn in CHECKS:
        _report(name, lambda fn=fn: fn(pkg), results)
    if args.rpc:
        _report("rpc_votes", lambda: check_rpc(pkg, args.rpc), results)
        _report("rpc_anchors", lambda: check_rpc_anchors(pkg, args.rpc, args.notary), results)
    ok = all(results)
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
