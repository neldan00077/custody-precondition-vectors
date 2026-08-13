#!/usr/bin/env python3
"""
Canonicalization known-answer self-test.

Point of this file: a serialiser that verifies against its own output is not a
verifier. The custody vectors assume a specific digest context — JCS (RFC 8785),
pinned in requirements.txt at an exact revision — and "JCS + SHA-256" is a family,
not a construction. Two conformant-looking JCS implementations still diverge on:

  * property ordering  — RFC 8785 §3.2.3 sorts by UTF-16 code units, NOT by
    Unicode code point; and
  * Unicode normalisation — RFC 8785 §3.1 performs NONE and preserves string
    data as-is.

Either difference alone gives the same object two digests. This test pins the two
edges to known bytes, so if the installed canonicalizer ever changes behaviour
the vectors silently depended on, this fails loudly instead of reinterpreting the
corpus. Run it before trusting a fresh environment.

Not a custody test. It exercises the substrate the custody vectors stand on.
"""

import hashlib
import sys

import rfc8785


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --- Edge A: ordering is by UTF-16 code units, not code point -----------------
# Key U+1F600 encodes in UTF-16 as the surrogate pair D83D DE00; its first code
# unit 0xD83D is below 0xFFFF, so it sorts BEFORE a U+FFFF key. A code-point sort
# (0x1F600 > 0xFFFF) would reverse them. This object makes the two orders diverge.
EDGE_A_OBJ = {"\U0001F600": 1, "\uFFFF": 2}
EDGE_A_BYTES = b'{"\xf0\x9f\x98\x80":1,"\xef\xbf\xbf":2}'
EDGE_A_DIGEST = "sha256:c6b1b96b618d8be475f379fe69c6646b44d7a5d3c01630c43509562f09d1024b"

# --- Edge B: no Unicode normalisation -----------------------------------------
# The value is "e" + U+0301 (combining acute), the DECOMPOSED form. A JCS
# implementation must preserve it; one that runs NFC would fold it to the
# precomposed U+00E9 ("é") and produce a different digest for the same logical
# string. The pinned bytes below still carry the combining mark (cc 81).
EDGE_B_OBJ = {"name": "e\u0301"}
EDGE_B_BYTES = b'{"name":"e\xcc\x81"}'
EDGE_B_DIGEST = "sha256:6a547588c4055916e090ed61467326046dd52810679d03bfb84d862a7123522e"


def check(label: str, obj, expected_bytes: bytes, expected_digest: str) -> bool:
    got = rfc8785.dumps(obj)
    ok_bytes = got == expected_bytes
    ok_digest = sha256_hex(got) == expected_digest
    ok = ok_bytes and ok_digest
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    if not ok_bytes:
        print(f"        bytes:  got {got!r}")
        print(f"                exp {expected_bytes!r}")
    if not ok_digest:
        print(f"        digest: got {sha256_hex(got)}")
        print(f"                exp {expected_digest}")
    return ok


def main() -> int:
    print(f"canonicalizer: rfc8785 {getattr(rfc8785, '__version__', '(version unknown)')}")
    results = [
        check("UTF-16 code-unit ordering (RFC 8785 §3.2.3)",
              EDGE_A_OBJ, EDGE_A_BYTES, EDGE_A_DIGEST),
        check("no Unicode normalisation (RFC 8785 §3.1)",
              EDGE_B_OBJ, EDGE_B_BYTES, EDGE_B_DIGEST),
    ]
    passed = sum(results)
    print(f"\n{passed}/{len(results)} canonicalization edges match pinned bytes.")
    if passed != len(results):
        print("Digest context has drifted. Do NOT trust the vectors in this "
              "environment until the canonicalizer is realigned.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
