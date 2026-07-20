#!/usr/bin/env python3
"""Unit + accuracy + performance tests for the DGA detector (valkyrie/dga.py).

Exit 0 on success, non-zero on failure (matches the standalone-script contract
tests/run_tests.py expects).

Three things are asserted:
  1. Unit behavior — registrable-label extraction, the bigram/entropy signals,
     and the corroboration gates fire (and don't) on named cases.
  2. Accuracy — recall/precision on a labeled corpus of long-label DGA vs. a
     HARD benign control set (CDN hash hostnames, odd-spelled brands, long
     dictionary/foreign domains). Precision MUST be 100% (the project rule: a
     false positive breaks a real site); recall must clear a documented floor.
  3. Performance — classification is a cheap pure function (throughput floor).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from valkyrie.dga import (
    classify_dga, registrable_label, rare_bigram_fraction, shannon_entropy,
)
from valkyrie.site_scanner import SiteScanner


# ── Labeled corpus ──────────────────────────────────────────────────────────
# Malicious: shape-faithful long-label DGA (necurs/ramnit/gozi/murofet/qakbot
# style — 12-24 char gibberish registrable label, some with interleaved digits).
DGA_DOMAINS = [
    "xjkqvw92hd8skwlqz3ty.com", "k2v9q3xw8pjh4m1tzr7f.top",
    "uqwxkcjznqvbhlpm.net", "myfpbcadkbfcdcj.com", "ffvknrgtcfdyjwq.ru",
    "vgnbhjklmqwrtzx.biz", "pxqzjvbnmkhgfdw.info", "zxcvbnmasdfghjk.com",
    "wlkjhgfdsapoiuy.net", "bqdzrxklmnpqvwst.org", "hjklzxcvbnmqwer.com",
    "a8f3k2j9d7h4l1q6.com", "kqjxvwzmbnhtplrd.su", "nvcxzlkjhgfdsaqw.com",
    "trewqasdfgzxcvbn.net", "zmxncbvlkajshdfg.com", "fdsrewqlkjhgtrew.net",
    "poiuytrewqlkjhgf.biz", "wsxzaqmlpknjbhuv.com",
]

# Benign: chosen to break a naive entropy/gibberish detector.
BENIGN_DOMAINS = [
    # CDN / cloud hash hostnames — gibberish SUBDOMAIN, legitimate 2LD.
    "d1anzknqnc1kmb.cloudfront.net", "dxbwzq9k3n7p2m.cloudfront.net",
    "prod-07-abcdxyz123.s3.amazonaws.com", "lh3.googleusercontent.com",
    "avatars0.githubusercontent.com", "scontent-iad3-1.xx.fbcdn.net",
    "media-exp1.licdn.com", "fonts.gstatic.com", "i.ytimg.com",
    # Real brands (some consonant-heavy / odd spelling).
    "netflix.com", "spotify.com", "flickr.com", "tumblr.com", "github.com",
    "cloudflare.com", "microsoft.com", "google.com", "amazon.com",
    "wikipedia.org", "linkedin.com", "instagram.com", "pinterest.com",
    "salesforce.com", "atlassian.com", "digitalocean.com", "stackoverflow.com",
    "grammarly.com", "crunchyroll.com", "kickstarter.com",
    # Long dictionary / compound / foreign legitimate domains (len >= 12).
    "washingtonpost.com", "bankofamerica.com", "internationalpaper.com",
    "nationalgeographic.com", "cambridgedictionary.org", "understandingwar.org",
    "merriamwebster.com", "schwarzenegger.com", "kryptowaehrungen.de",
    "gesundheitsministerium.at", "przedsiebiorstwo.pl", "electroencephalography.org",
    # Hyphenated legitimate brands (hyphens must not inflate the score).
    "libjpeg-turbo.org", "coca-cola.com", "real-estate-services.com",
    "t-mobile.com",
]

# Documented recall floor for this corpus. Keyboard-walk-style DGAs are a known
# limitation (see valkyrie/dga.py honest boundary); this floor reflects strong
# recall on PRNG-style families without pretending to catch every shape.
RECALL_FLOOR = 0.70
THROUGHPUT_FLOOR = 20_000     # classifications/sec (pure function, must be cheap)


def _check(cond: bool, msg: str, fails: list) -> None:
    if not cond:
        fails.append(msg)


def test_unit(fails: list) -> None:
    print("\n-- unit: label extraction / signals / gates --")
    # Registrable label: subdomain ignored; multi-part suffix handled.
    _check(registrable_label("d1anzknqnc1kmb.cloudfront.net") == "cloudfront",
           "registrable_label should return the 2LD, not the subdomain", fails)
    _check(registrable_label("xjkqvw92hd8skwlqz3ty.com") == "xjkqvw92hd8skwlqz3ty",
           "registrable_label of a bare 2LD", fails)
    _check(registrable_label("random-gibberish-xyz.co.uk") == "random-gibberish-xyz",
           "registrable_label should skip a two-label public suffix (co.uk)", fails)
    # Signal sanity: gibberish >> real word on the rare-bigram axis.
    _check(rare_bigram_fraction("xjkqvwzhdskwlqzty") > 0.6,
           "gibberish should have a high rare-bigram fraction", fails)
    _check(rare_bigram_fraction("washingtonpost") < 0.3,
           "a real dictionary word should have a low rare-bigram fraction", fails)
    # Hyphens must not inflate: a hyphenated brand stays well below the floor.
    _check(not classify_dga("real-estate-services.com").is_dga,
           "hyphenated legitimate brand must not be classified DGA", fails)
    # Entropy is monotone-ish sane.
    _check(shannon_entropy("aaaaaa") < 1.0 < shannon_entropy("abcdef"),
           "entropy of repeated vs varied string", fails)
    # A clear DGA fires with block-worthy confidence; a clear brand does not.
    r = classify_dga("xjkqvw92hd8skwlqz3ty.com")
    _check(r.is_dga and r.confidence >= 0.70,
           f"clear DGA must fire block-worthy (got {r.is_dga}/{r.confidence})", fails)
    _check(not classify_dga("microsoft.com").is_dga,
           "a mainstream brand must never be DGA", fails)
    print(f"   unit assertions checked ({len(fails)} failure(s) so far)")


def test_accuracy(fails: list) -> None:
    print("\n-- accuracy: recall / precision on the labeled corpus --")
    tp = sum(1 for d in DGA_DOMAINS if classify_dga(d).is_dga)
    fn = len(DGA_DOMAINS) - tp
    fp = sum(1 for d in BENIGN_DOMAINS if classify_dga(d).is_dga)
    tn = len(BENIGN_DOMAINS) - fp
    recall = tp / len(DGA_DOMAINS)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    print(f"   recall={recall*100:.1f}%  precision={precision*100:.1f}%  "
          f"(TP={tp} FN={fn} FP={fp} TN={tn})")
    if fp:
        print("   FALSE POSITIVES:", [d for d in BENIGN_DOMAINS if classify_dga(d).is_dga])
    # Precision is the hard gate — a benign false positive is unacceptable.
    _check(fp == 0, f"precision must be 100% — {fp} benign false positive(s)", fails)
    _check(recall >= RECALL_FLOOR,
           f"recall {recall*100:.1f}% below floor {RECALL_FLOOR*100:.0f}%", fails)


def test_pipeline(fails: list) -> None:
    print("\n-- integration: scanner blocks DGA as category 'dga' --")
    sc = SiteScanner(store=None)
    r = sc.analyze("xjkqvw92hd8skwlqz3ty.com", "chrome.exe")
    _check(r.decision == "block" and r.category == "dga",
           f"scanner should block DGA with cat=dga (got {r.decision}/{r.category})", fails)
    # Regression: CDN hostname and mainstream sites still allowed.
    for d in ("d1anzknqnc1kmb.cloudfront.net", "chase.com", "github.com"):
        _check(sc.analyze(d, "chrome.exe").decision == "allow",
               f"{d} must still be allowed after DGA wiring", fails)
    print("   scanner integration checked")


def test_perf(fails: list) -> None:
    print("\n-- performance: pure-function throughput --")
    domains = (DGA_DOMAINS + BENIGN_DOMAINS) * 50
    start = time.perf_counter()
    for d in domains:
        classify_dga(d)
    elapsed = time.perf_counter() - start
    rate = len(domains) / elapsed
    print(f"   {len(domains)} classifications in {elapsed*1000:.1f} ms "
          f"= {rate:,.0f}/s")
    _check(rate >= THROUGHPUT_FLOOR,
           f"throughput {rate:,.0f}/s below floor {THROUGHPUT_FLOOR:,}/s", fails)


def main() -> int:
    print("Valkyrie DGA detector test")
    print("=" * 60)
    fails: list = []
    test_unit(fails)
    test_accuracy(fails)
    test_pipeline(fails)
    test_perf(fails)

    print("\n" + "=" * 60)
    if fails:
        print(f"  RESULT: {len(fails)} FAILURE(S)")
        for f in fails:
            print(f"   - {f}")
        return 1
    print("  RESULT: ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
