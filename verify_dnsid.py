#!/usr/bin/env python3
"""verify_dnsid.py -- independently verify a DNSid-anchored agent and its
signed work product. ANYONE can run this; it needs no account, no local AI
system, and no trust in the publisher. deps: pip install pynacl dnspython requests

Online (the real demo):
    python3 verify_dnsid.py herald.tree3vocations.com
Offline dry-run (local site dir + record file, no network):
    python3 verify_dnsid.py herald.tree3vocations.com \
        --record-file record.txt --site-dir site

Implements draft-ihsanullah-dnsid-00 interactive verification (section 9.1
steps 1-3 + status check) and historical/provenance verification (section 9.2)
against the tree3demo hash-chained ledger. Ed25519 (RFC 8037) signatures.
"""
import argparse, base64, hashlib, json, sys

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

OK, BAD = "\u2714", "\u2718"
failures = 0


def report(ok: bool, msg: str):
    global failures
    print(f"  {OK if ok else BAD} {msg}")
    if not ok:
        failures += 1


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical_json(body: dict, exclude=("signature",)) -> bytes:
    """Mirror of the publisher's canonical form (cnp_crypto.canonical_bytes):
    drop excluded keys, sorted-key whitespace-free JSON, UTF-8."""
    clean = {k: v for k, v in body.items() if k not in exclude}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def verify_body(vk: VerifyKey, body: dict) -> bool:
    try:
        vk.verify(canonical_json(body), b64u_decode(body["signature"]))
        return True
    except (BadSignatureError, KeyError, ValueError):
        return False


def parse_record(raw: str) -> dict:
    tags = {}
    for part in raw.strip().split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"malformed tag (no '='): {part!r}")
        k, v = part.split("=", 1)
        if k in tags:
            raise ValueError(f"duplicate tag {k!r} -- verifier MUST reject")
        tags[k] = v
    return tags


def fetch_record_dns(fqdn: str) -> str:
    import dns.resolver
    owner = f"_dnsid.{fqdn}"
    answers = dns.resolver.resolve(owner, "TXT")
    rrs = list(answers)
    if len(rrs) != 1:
        raise ValueError(f"{len(rrs)} TXT records at {owner} -- singleton required, MUST fail")
    # section 5.8: concatenate all character-strings, no separator
    return b"".join(rrs[0].strings).decode("ascii")


def fetch_url(url: str) -> bytes:
    import requests
    r = requests.get(url, timeout=15, allow_redirects=False)
    if 300 <= r.status_code < 400:
        raise ValueError(f"redirect from {url} -- MUST NOT follow (section 12.7)")
    r.raise_for_status()
    return r.content


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fqdn", help="agent FQDN, e.g. herald.tree3vocations.com")
    ap.add_argument("--record-file", help="offline: read TXT value from file instead of DNS")
    ap.add_argument("--site-dir", help="offline: read endpoints from local dir instead of HTTPS")
    args = ap.parse_args()
    offline = bool(args.site_dir)

    def get(url_path: str) -> bytes:
        """url_path like '/.well-known/jwks.json' -- local file offline, HTTPS online."""
        if offline:
            import os
            return open(os.path.join(args.site_dir, url_path.lstrip("/")), "rb").read()
        return fetch_url(f"https://{args.fqdn}{url_path}")

    print(f"\nDNSid verification: {args.fqdn}"
          f"  [{'OFFLINE dry-run' if offline else 'live DNS + HTTPS'}]\n")

    # -- step 1: resolve and parse the record --------------------------------
    try:
        raw = (open(args.record_file).read() if args.record_file
               else fetch_record_dns(args.fqdn))
        tags = parse_record(raw)
        report(True, f"DNS record found and parsed ({len(tags)} tags)")
    except Exception as e:
        report(False, f"record retrieval/parse: {e}")
        return finish()

    # -- step 2: structural checks -------------------------------------------
    report(raw.strip().startswith("v=DNSid1"), 'version tag "v=DNSid1" is first')
    missing = [t for t in ("v", "oi", "ku", "lr", "su", "sg") if not tags.get(t)]
    report(not missing, "all REQUIRED tags present and non-empty"
           + (f" (missing: {missing})" if missing else ""))
    if missing:
        return finish()

    # -- step 3: fetch JWKS, verify entity signature -------------------------
    try:
        jwks = json.loads(get("/.well-known/jwks.json"))
        keys = [k for k in jwks["keys"] if k.get("kty") == "OKP"
                and k.get("crv") == "Ed25519"]
        report(bool(keys), f"JWKS fetched ({len(jwks['keys'])} key(s), "
                           f"{len(keys)} Ed25519)")
        canon = ";".join(f"{k}={tags[k]}" for k in sorted(tags) if k != "sg")
        sig = b64u_decode(tags["sg"])
        vk = None
        for k in keys:
            candidate = VerifyKey(b64u_decode(k["x"]))
            try:
                candidate.verify(canon.encode("ascii"), sig)
                vk = candidate
                report(True, f'entity signature valid (kid: {k.get("kid", "?")}, '
                             f'oi: {tags["oi"]})')
                break
            except BadSignatureError:
                continue
        if vk is None:
            report(False, "entity signature: no JWKS key validates the sg tag")
            return finish()
    except Exception as e:
        report(False, f"JWKS/signature step: {e}")
        return finish()

    # -- status check ---------------------------------------------------------
    try:
        status = json.loads(get("/.well-known/dnsid-status"))
        report(status.get("state") == "ACTIVE",
               f'status: {status.get("state")} (last transition '
               f'{status.get("last_transition")})')
    except Exception as e:
        report(False, f"status endpoint: {e}")

    # -- historical: ledger chain + entry signatures --------------------------
    try:
        method, _, loc = tags["lr"].partition(":")
        ledger = json.loads(get("/ledger.json") if offline or not loc.startswith("http")
                            else fetch_url(loc))
        entries = ledger["entries"]
        chain_ok, sig_ok, prev = True, True, None
        for e in entries:
            if e["prev_hash"] != prev:
                chain_ok = False
            if not verify_body(vk, e):
                sig_ok = False
            prev = hashlib.sha256(json.dumps(
                e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        report(chain_ok, f"ledger hash-chain intact ({len(entries)} entries, "
                         f"method {method!r})")
        report(sig_ok, "every ledger entry signed by the anchored key")
        issuance = any(e["event"] == "ISSUANCE" for e in entries)
        report(issuance, "ISSUANCE event on record")
    except Exception as e:
        report(False, f"ledger step: {e}")
        return finish()

    # -- provenance: the signed work product ----------------------------------
    try:
        cs = next(e for e in entries if e["event"] == "CONTENT_SIG")
        art_bytes = get("/artifacts/statement.json")
        got = "sha256:" + hashlib.sha256(art_bytes).hexdigest()
        report(got == cs["content_hash"],
               "artifact hash matches the ledger CONTENT_SIG entry")
        artifact = json.loads(art_bytes)
        report(verify_body(vk, artifact), "artifact signature valid "
               f'(agent: {artifact.get("agent")})')
        print(f'\n  artifact says: "{artifact.get("content")}"')
    except StopIteration:
        report(False, "no CONTENT_SIG event in ledger")
    except Exception as e:
        report(False, f"provenance step: {e}")

    return finish()


def finish():
    print()
    if failures == 0:
        print("RESULT: all checks passed.")
        print("-> This artifact was produced by an agent accountable to the")
        print("   registrant of the anchoring domain -- verified with nothing")
        print("   but public DNS, HTTPS, and open-source cryptography.")
        sys.exit(0)
    print(f"RESULT: {failures} check(s) FAILED. Do not trust this identity/artifact.")
    sys.exit(1)


if __name__ == "__main__":
    main()
