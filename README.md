# Custody Precondition Vectors (v0.1)

A small, deterministically regenerable conformance set that isolates **one**
question the evidence-envelope layer cannot answer by itself:

> Is the capturer's identity **issuer-established** or **self-asserted**, and
> what may a verifier conclude from each?

This is the *provenance* precondition beneath the custody axis
(`same_domain` / `deployer_domain` / `independent_third_party`). Grading the
independence of a capturer is empty if the capturer's identity is asserted by
the same runtime that authored the entry. These vectors make that failure
mode testable, and pin exactly one outcome per edge.

Baseline matches the thread it comes from: **JCS (RFC 8785) + SHA-256**,
signatures **Ed25519 (RFC 8032)**. `python3 generate.py` regenerates the corpus
byte-for-byte; `python3 verify.py` re-derives every outcome from the envelopes.

## The rule (the whole of it)

A verifier MUST NOT grant a capturer more custody weight than its identity
provenance supports.

| provenance | how it is backed | ceiling it can support |
|---|---|---|
| `issuer_established` | attestation signed by an authority **external to the executor**, verifying against that authority's key | `independent_third_party` |
| `self_asserted` | only the runtime that authored the entry vouches for the capturer | `same_domain` |
| unestablished (missing/invalid attestation) | nothing verifiable | — (fails closed) |

If the **declared** `trust_domain` exceeds the ceiling the provenance supports,
the record **fails closed**. An `issuer_established` claim whose attestation does
not verify collapses to unestablished and fails closed.

The attestation binds `(capturer_id, issuer_id, action_key)`, so it is not a
reusable badge: it attests *this* capturer for *this* governed action and cannot
be lifted onto another.

## The vectors

All four share an identical decision core (same `action_key`, governed input,
policy snapshot, verdict, outcome). **Only the custody block differs** — which is
the point: same decided facts, different provenance, different verdict.

| vector | provenance | declares | attestation | `overall_valid` | what it proves |
|---|---|---|---|---|---|
| `01_issuer_established_independent` | issuer_established | independent_third_party | valid, external issuer | **true** | independence is grantable only when an external issuer established the identity |
| `02_self_asserted_overclaim` | self_asserted | independent_third_party | none | **false** | a self-asserted capturer cannot buy independence; overclaim fails closed |
| `03_self_asserted_honest` | self_asserted | same_domain | none | **true** | self-asserted is a *valid record* — it just earns no independence. The rule caps, it does not void |
| `04_forged_attestation` | issuer_established | independent_third_party | signature by executor key, issuer key presented | **false** | the compromised-runtime case: a runtime minting an `issuer_established` claim it cannot sign is caught, because it does not hold the issuer key |

Vector 03 is deliberately a **pass**: the claim is that self-asserted provenance
cannot support *independence*, not that self-asserted records are void. Vector 04
is the one that bites — it is the "a compromised runtime mints perfectly-graded
fields for an identity it issued to itself" case, failing because the executor
does not hold the issuer key.

## Reproduce

```
pip install -r requirements.txt
python3 generate.py     # writes vectors/, byte-identical each run
python3 verify.py       # 4/4 vectors verify as specified
```

Third-party digest check (no Python needed), matching the published values in
each `expected.json` and in `MANIFEST.sha256.json`:

```
sha256sum vectors/01_issuer_established_independent/canonical.bytes
```

The issuer public key is published at `vectors/issuer_pubkey.txt` so anyone can
verify the attestations in vectors 01 and 04 without trusting this repository.

## Scope — what this does and does not establish

Stated plainly, because the distinction is the contribution:

* It **does** let a verifier read, from the record alone, whether a capturer's
  identity was issuer-established or self-asserted, and refuse independence to
  the latter — without relying on tribal knowledge.
* It **does not** prove the issuer is honest, nor that the runtime stayed
  faithful *after* activation. Provenance is **necessary** for an independence
  claim, not **sufficient** for faithful capture. The witness/attestation
  mechanism itself is an L2 concern; what belongs in the L1 record is the typed,
  load-bearing declaration this set exercises.
* Truth of the outcome is **out of scope** (cf. the attested/corroborated
  distinction raised in the thread). These vectors test the *evidentiary
  sufficiency* of the custody claim, not whether the world matched it. The
  outcome carries a corroboration handle for that separate axis.

## Relationship to the neutral envelope / Golden Trace

The custody fields here map onto the custody axis proposed for the neutral
envelope (capturer, capture moment relative to execution, capturer-to-executor
trust domain). This set is offered as a **precondition driver** that can plug
into the Golden Trace corpus and the `agent-governance-testvectors` shape
(`{envelope.json, expected.json}` per case, `expected.json` recording the
verification outcome). It is intended to live in a maintainer-neutral venue, not
inside any single implementation — including ours.

## Reference implementation caveat

`generate.py` and `verify.py` are a single reference implementation. Byte-identity
here is internal consistency, not cross-implementation conformance. The vectors
are pinned under `MANIFEST.sha256.json` and recomputable from `canonical.bytes`
with any SHA-256 tool, so an implementation written from this README alone, by a
different author, can match them or report a concrete divergence. Independent
verification is invited; divergences are the useful output.

## Authorship & license

The **provenance precondition** and the **capturer-to-executor custody axis**
(`same_domain` / `deployer_domain` / `independent_third_party`) originate with
Dani Danwin (TrustLayers), first stated in the Microsoft `agent-governance-toolkit`
discussion #276 (July 2026). Reuse of the primitive shape is welcome under the
license below; per-component citation back to origin is the only request.

- Spec text and vectors: **CC-BY-4.0**
- Code (`generate.py`, `verify.py`): **Apache-2.0**

Contact: Dani Danwin — TrustLayers.eu
