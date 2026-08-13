#!/usr/bin/env python3
"""
Custody Precondition Vectors — reference verifier.

Implements ONE conformance rule and nothing more:

    A verifier MUST NOT grant a capturer more custody weight than its identity
    provenance supports.

      provenance = issuer_established  (attestation by an authority external to
                                        the executor, verifying against that
                                        authority's key)
          -> may support up to  independent_third_party
      provenance = self_asserted       (only the runtime that authored the entry
                                        vouches for the capturer)
          -> capped at          same_domain

    If the declared trust_domain exceeds what provenance supports, the record
    FAILS CLOSED. If an issuer_established claim's attestation does not verify,
    provenance collapses to unestablished and the record FAILS CLOSED.

Scope, stated honestly:
  * This checks the record's *self-consistency about independence*. It does not
    prove the issuer is honest, nor that the runtime stayed faithful after
    activation. Provenance is necessary for an independence claim, not
    sufficient for faithful capture.
  * Truth of the outcome is out of scope (see parweb's attested/corroborated
    point). This verifier tests evidentiary sufficiency of the custody claim.
"""

import base64
import hashlib
import json
import os
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VECTORS = os.path.join(os.path.dirname(__file__), "vectors")

RANK = {"same_domain": 1, "deployer_domain": 2, "independent_third_party": 3}


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def load_issuer_pub(pub_field: str) -> Ed25519PublicKey:
    assert pub_field.startswith("ed25519:")
    raw = base64.b64decode(pub_field.split(":", 1)[1])
    return Ed25519PublicKey.from_public_bytes(raw)


def attestation_valid(att: dict, action_key: str) -> bool:
    """Recompute the signed binding and verify it against the STATED issuer key.

    The binding commits to (capturer_id, issuer_id, action_key), so an
    attestation cannot be lifted onto a different capturer or a different action.
    A runtime that does not hold the issuer key cannot produce a valid signature
    here, which is the whole point.
    """
    try:
        binding_obj = {
            "capturer_id": att["_capturer_id"],
            "issuer_id": att["issuer_id"],
            "action_key": action_key,
        }
        binding_bytes = jcs(binding_obj)
        if sha256_hex(binding_bytes) != att["binding"]:
            return False
        pub = load_issuer_pub(att["issuer_pubkey"])
        pub.verify(base64.b64decode(att["signature"]), binding_bytes)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def verify(env: dict) -> dict:
    custody = env["custody"]
    capturer = custody["capturer"]
    action_key = env["decision"]["action_key"]
    declared = custody["trust_domain"]
    provenance = capturer.get("provenance")

    att_valid = False
    resolved = provenance

    if provenance == "issuer_established":
        att = capturer.get("issuer_attestation")
        if not att:
            resolved = "unestablished"
        else:
            att = dict(att)
            att["_capturer_id"] = capturer["id"]
            # an issuer whose key sits inside the executor's domain is not external
            issuer_is_external = att.get("issuer_id") != custody.get("executor_id")
            att_valid = issuer_is_external and attestation_valid(att, action_key)
            if not att_valid:
                resolved = "unestablished"

    # ceiling that provenance can support
    if resolved == "issuer_established":
        ceiling = "independent_third_party"
    elif resolved == "self_asserted":
        ceiling = "same_domain"
    else:  # unestablished / forged
        ceiling = None

    # machine-readable outcome code, null on success. A MUST-FAIL vector is only
    # testable as a rejection if the reason it rejects is pinned and switchable.
    if ceiling is None:
        failure_code = "ATTESTATION_INVALID"
    elif RANK[declared] > RANK[ceiling]:
        failure_code = "PROVENANCE_INSUFFICIENT_FOR_DECLARED_TRUST_DOMAIN"
    else:
        failure_code = None

    if failure_code is not None:
        return {
            "provenance_resolved": provenance,
            "issuer_attestation_valid": att_valid,
            "declared_trust_domain": declared,
            "custody_weight_granted": None,
            "overall_valid": False,
            "failure_code": failure_code,
        }

    return {
        "provenance_resolved": provenance,
        "issuer_attestation_valid": att_valid,
        "declared_trust_domain": declared,
        "custody_weight_granted": declared,
        "overall_valid": True,
        "failure_code": None,
    }


COMPARED = [
    "provenance_resolved",
    "issuer_attestation_valid",
    "declared_trust_domain",
    "custody_weight_granted",
    "overall_valid",
    "failure_code",
]


def main() -> int:
    cases = sorted(
        d for d in os.listdir(VECTORS) if os.path.isdir(os.path.join(VECTORS, d))
    )
    failures = 0
    for name in cases:
        d = os.path.join(VECTORS, name)
        with open(os.path.join(d, "envelope.json")) as f:
            env = json.load(f)
        with open(os.path.join(d, "expected.json")) as f:
            expected = json.load(f)

        # confirm the published digest matches the canonical bytes
        digest = sha256_hex(jcs(env))
        digest_ok = digest == expected.get("envelope_digest")

        got = verify(env)
        mismatch = {k: (got[k], expected[k]) for k in COMPARED if got[k] != expected[k]}

        ok = digest_ok and not mismatch
        print(f"[{'PASS' if ok else 'FAIL'}] {name}  overall_valid={got['overall_valid']}")
        if not digest_ok:
            print(f"        digest mismatch: {digest} != {expected.get('envelope_digest')}")
        for k, (g, e) in mismatch.items():
            print(f"        {k}: got {g!r}, expected {e!r}")
        failures += 0 if ok else 1

    print(f"\n{len(cases) - failures}/{len(cases)} vectors verify as specified.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
