# OGDOGE DAO vote verifier

Recount an OGDOGE DAO community vote yourself, without trusting the voting site's server.

When a vote closes, the voting site publishes an **audit package** (`audit.zip`) with every vote, every
balance snapshot, the exclusion list and the admin log. While the vote was running, fingerprints of all of
it were recorded on Solana by the notary wallet. This script recomputes the result from scratch, checks the
package against those fingerprints and, with `--rpc`, confirms on Solana itself that every vote and every
fingerprint is really there.

## Run it

You need Python 3.10 or newer.

```bash
pip install -r requirements.txt
python verify.py audit.zip
```

To also check everything directly on Solana, pass any Solana RPC URL and the notary wallet address shown
on the voting site:

```bash
python verify.py audit.zip --rpc https://api.mainnet-beta.solana.com --notary <NOTARY_ADDRESS>
```

It prints `PASS` or `FAIL` for each check and exits with code 0 only when every check passes.

## What it checks

| Check | What it proves |
|---|---|
| `content_hash` | The proposal text and options are the ones that were fingerprinted |
| `hash_chain` | The admin log was not edited, reordered or cut |
| `publish` | The proposal was published with its rules, as logged |
| `exclusions` | The exclusion list is the one frozen when the vote was published |
| `snapshots` | Every balance snapshot matches its recorded hash and merkle root |
| `sessions` | Every voting address was issued as logged |
| `deposits` | Every deposit matches its voting address and the log |
| `votes` | Every counted vote comes from a valid deposit in the voting window |
| `tally` | The result recomputed from the data above matches the published result |
| `tally_anchor` | The final result matches the result fingerprint listed in the package |
| `rpc_votes` (with `--rpc`) | Every vote is a real Solana transaction from that wallet, re-validated on-chain |
| `rpc_anchors` (with `--rpc`) | Every fingerprint is a real Solana transaction with that exact memo, all paid by the notary wallet, including the publication, exclusion list and final result |

Without `--rpc` the script trusts the transaction ids listed in the package; with `--rpc` it trusts only Solana.

Voting power is each wallet's lowest OGDOGE balance from the eligibility snapshot to the close, so tokens
moved or sold during the vote do not count.

## Files

`verify.py` is the verifier. `ogdao/chain/txparse.py` and `ogdao/constants.py` are the deposit validator
used by the voting server, copied unchanged so the on-chain check is exactly the same rule. `SHA256SUMS`
lists the fingerprint of every file in this release.

Results are a community signal; see the OGDOGE DAO Constitution for how they are used.

## License

MIT. See [LICENSE](LICENSE).
