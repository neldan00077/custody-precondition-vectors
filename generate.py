#!/usr/bin/env python3
"""
Custody Precondition Vectors — generator.

Produces four conformance vectors that isolate ONE question the envelope layer
cannot answer by itself: is the capturer's identity issuer-established or
self-asserted, and what may a verifier conclude from each.

Design notes
------------
* Canonicalization: RFC 8785 (JCS) + SHA-256, matching the thread baseline.
* Signatures: Ed25519 (RFC 8032), deterministic, so regeneration is byte-identical.
* Keys are FIXED TEST SEEDS, clearly marked. They exist only so the corpus
  regenerates bit-for-bit. Real deployments use real keys.
* The non-custody core (decision, action_key, policy snapshot, outcome) is
  IDENTICAL across the "independent" cases, so the only variable is provenance.
  That demonstrates the claim directly: same decided facts, different custody
  provenance -> different verifier conclusion.

This file is deterministic: `python3 generate.py` twice yields identical bytes.
"""

import base64
import hashlib
import json
import os

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

OUT = os.path.join(os.path.dirname(__file__), "vectors")

# --- FIXED TEST-ONLY KEY SEEDS (NOT SECRETS; present only for determinism) ----
ISSUER_SEED = bytes.fromhex(
    "00" * 31 + "11"  # issuing authority, external to the executor's trust domain
)
EXECUTOR_SEED = bytes.fromhex(
    "00" * 31 + "22"  # the runtime that authored the entry
)


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def pubkey_b64(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes_raw()
    return "ed25519:" + b64(raw)


issuer_sk = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED)
executor_sk = Ed25519PrivateKey.from_private_bytes(EXECUTOR_SEED)

ISSUER_ID = "did:web:issuer.aegf.example"          # external issuing authority
EXECUTOR_ID = "did:web:runtime.deployer.example"   # the governed runtime
CAPTURER_ID = "agent:passport:8f21c4"              # the capturer whose identity is in question


# --- shared, custody-independent decision core --------------------------------
# action_key is content-addressed over the governed action (Mycelium-style),
# and re-bound identically in the outcome so decision<->outcome is not just
# timestamp correlation.
action_preimage = {
    "action_type": "PAYMENT_INITIATE",
    "agent_id": CAPTURER_ID,
    "scope": "sepa_instant:eur",
    "resource": "iban:DE00_TEST",
}
ACTION_KEY = sha256_hex(jcs(action_preimage))

governed_input = {"amount_eur": 4200, "beneficiary": "acme-gmbh", "mandate": "M-0007"}
GOVERNED_INPUT_HASH = sha256_hex(jcs(governed_input))

DECISION_CORE = {
    "action_key": ACTION_KEY,
    "governed_input_hash": GOVERNED_INPUT_HASH,
    "policy": {"id": "eu-ai-act.art14.human_oversight", "version": "2026-07-27"},
    "verdict": "allow",
}

OUTCOME_CORE = {
    "action_key": ACTION_KEY,  # re-binds the SAME key
    "result": "executed",
    "corroboration": {
        # nod to parweb: a handle a third party can fetch that is NOT the write response
        "state": "source_system_corroborated",
        "handle": "https://settlement.example/receipts/ST-0007",
    },
}


def issuer_attestation(capturer_id: str, signer_sk: Ed25519PrivateKey, issuer_pub: str):
    """
    An issuing authority signs a binding over the capturer identity + the action_key.
    Binding the action_key means the attestation is not a reusable generic badge:
    it attests THIS capturer for THIS governed action.
    """
    binding_obj = {
        "capturer_id": capturer_id,
        "issuer_id": ISSUER_ID,
        "action_key": ACTION_KEY,
    }
    binding_bytes = jcs(binding_obj)
    binding_digest = sha256_hex(binding_bytes)
    signature = signer_sk.sign(binding_bytes)
    return {
        "issuer_id": ISSUER_ID,
        "issuer_pubkey": issuer_pub,
        "alg": "ed25519",
        "binding": binding_digest,
        "signature": b64(signature),
    }


def envelope(custody: dict) -> dict:
    return {
        "schema": "trustlayers.custody-precondition/v0.1",
        "decision": DECISION_CORE,
        "outcome": OUTCOME_CORE,
        "custody": custody,
    }


# --- CASE 1: issuer-established provenance, declares independence -> PASS ------
c1_custody = {
    "capturer": {
        "id": CAPTURER_ID,
        "provenance": "issuer_established",
        "issuer_attestation": issuer_attestation(
            CAPTURER_ID, issuer_sk, pubkey_b64(issuer_sk)
        ),
    },
    "executor_id": EXECUTOR_ID,
    "capture_moment": "pre_execution",
    "trust_domain": "independent_third_party",
}

# --- CASE 2: self-asserted, declares independence (overclaim) -> FAIL ----------
c2_custody = {
    "capturer": {
        "id": CAPTURER_ID,
        "provenance": "self_asserted",
    },
    "executor_id": EXECUTOR_ID,
    "capture_moment": "pre_execution",
    "trust_domain": "independent_third_party",  # declaration exceeds provenance
}

# --- CASE 3: self-asserted, declares same_domain (honest) -> PASS, capped ------
c3_custody = {
    "capturer": {
        "id": CAPTURER_ID,
        "provenance": "self_asserted",
    },
    "executor_id": EXECUTOR_ID,
    "capture_moment": "pre_execution",
    "trust_domain": "same_domain",  # honest about the position it is in
}

# --- CASE 4: forged attestation (executor signs, presents issuer key) -> FAIL --
# The compromised-runtime case: the runtime mints an "issuer_established" claim
# but does not hold the issuer key, so the signature does not verify.
forged = issuer_attestation(CAPTURER_ID, executor_sk, pubkey_b64(issuer_sk))
c4_custody = {
    "capturer": {
        "id": CAPTURER_ID,
        "provenance": "issuer_established",
        "issuer_attestation": forged,  # issuer_pubkey stated, but signed by executor key
    },
    "executor_id": EXECUTOR_ID,
    "capture_moment": "pre_execution",
    "trust_domain": "independent_third_party",
}


CASES = {
    "01_issuer_established_independent": (
        c1_custody,
        {
            "provenance_resolved": "issuer_established",
            "issuer_attestation_valid": True,
            "declared_trust_domain": "independent_third_party",
            "custody_weight_granted": "independent_third_party",
            "overall_valid": True,
            "reason": "issuer-established provenance, attestation verifies against issuer key external to executor; declared independence is supported",
        },
    ),
    "02_self_asserted_overclaim": (
        c2_custody,
        {
            "provenance_resolved": "self_asserted",
            "issuer_attestation_valid": False,
            "declared_trust_domain": "independent_third_party",
            "custody_weight_granted": None,
            "overall_valid": False,
            "reason": "provenance_insufficient_for_declared_trust_domain: self-asserted capturer identity cannot support an independent-third-party declaration; fails closed",
        },
    ),
    "03_self_asserted_honest": (
        c3_custody,
        {
            "provenance_resolved": "self_asserted",
            "issuer_attestation_valid": False,
            "declared_trust_domain": "same_domain",
            "custody_weight_granted": "same_domain",
            "overall_valid": True,
            "reason": "self-asserted capturer, declaration does not exceed provenance; valid record, no independence granted",
        },
    ),
    "04_forged_attestation": (
        c4_custody,
        {
            "provenance_resolved": "issuer_established",
            "issuer_attestation_valid": False,
            "declared_trust_domain": "independent_third_party",
            "custody_weight_granted": None,
            "overall_valid": False,
            "reason": "attestation_invalid: signature does not verify against stated issuer key (runtime does not hold the issuer key it claims); fails closed",
        },
    ),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = {}
    for name, (custody, expected) in CASES.items():
        env = envelope(custody)
        canon = jcs(env)
        digest = sha256_hex(canon)
        d = os.path.join(OUT, name)
        os.makedirs(d, exist_ok=True)
        # pretty envelope for humans
        with open(os.path.join(d, "envelope.json"), "w") as f:
            json.dump(env, f, indent=2, sort_keys=True)
            f.write("\n")
        # the exact canonical bytes an auditor recomputes
        with open(os.path.join(d, "canonical.bytes"), "wb") as f:
            f.write(canon)
        with open(os.path.join(d, "expected.json"), "w") as f:
            out = dict(expected)
            out["envelope_digest"] = digest
            json.dump(out, f, indent=2, sort_keys=True)
            f.write("\n")
        manifest[name] = digest

    with open(os.path.join(OUT, "MANIFEST.sha256.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    # publish the issuer public key so a third party can verify the attestations
    with open(os.path.join(OUT, "issuer_pubkey.txt"), "w") as f:
        f.write(pubkey_b64(issuer_sk) + "\n")

    print("Generated vectors:")
    for k, v in manifest.items():
        print(f"  {k}: {v}")
    print("issuer_pubkey:", pubkey_b64(issuer_sk))


if __name__ == "__main__":
    main()
