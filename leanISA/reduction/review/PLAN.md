# leanISA claim-reduction review

Status: design review only. No reduction implementation or accepting proof has
been reviewed yet.

Backend: unchanged leanVM `575df819d9c857f38068cecf7b1640e0ce4bfb29`, including
the specialised Keccak circuit. The new code must be isolated from the archived
wrapper and its existing benchmark reports.

## Intended statement

A received root proves the approved signature relation for every intended
public key/message pair, together with every descendant proof's remaining
bytecode obligation. Instead of an external record for every edge, each merge
proves a sumcheck reduction to one claim per required trusted program family.
The final native receiver evaluates those reduced claims against independently
approved program tables and verifies the root under its approved identity.

The producer controls all advice, child proofs, inherited records, sumcheck
messages, claimed terminal values and the received envelope. It cannot choose
the receiver's intended records, program tables or approved wrapper identities.

## Required bindings

1. Fresh claims come from the actual in-guest `verify_sub` outputs. Separate
   advice carrying a matching-looking claim is insufficient.
2. A child's inherited record is authenticated by reconstructing that child's
   public-input digest and using that exact digest in `verify_sub`.
3. Required families, dimensions, claim counts and ordering follow the trusted
   node schema. No prover-selected mask may omit an outstanding claim.
4. Every point and value retains all 192 field bits. Hash packing must constrain
   its limb hints, including the third limb; digest cells remain canonical.
5. The reduction transcript binds all input claims, program identities,
   dimensions and child public inputs before the batching challenge.
6. Every round's messages are bound before its challenge. The final point is
   transcript-derived, not freely supplied by the producer.
7. Characteristic-two degree-two rounds use
   `c1 = running_claim + c2` and
   `next = c0 + z*(running_claim+c2) + z*z*c2`.
8. The terminal identity multiplies the new polynomial value by the batched eq
   weight. It must not divide by that weight or assume it is nonzero.
9. The new point and terminal value are included in the merge's public-input
   digest, alongside the application/public-claim digest and protocol context.
10. Root acceptance evaluates each final claim against its actual trusted
    bytecode table. It never accepts a producer-chosen terminal value alone.

Semantic digest separation is also required to reduce transport. A node's full
public input should hash its trusted configuration, application digest and
reduced record. Its application digest combines child application digests,
without child accumulator records. Inside a parent, each hinted child record
must reconstruct the full child public input used by `verify_sub`. At the root,
the receiver can then derive the application digest from intended leaf records
and receive only the root's reduced record. Continuing to hash full child
public inputs into the application digest would require intermediate record
preimages at the receiver and retain O(E) auxiliary transport despite reducing
the polynomial evaluations.

The number of program families may grow with depth or program variants. A
bounded-depth implementation must report that fact rather than claim constant
verification work automatically. Building different wrapper programs bottom-up
avoids requiring a program to contain its own unknown hash.

## Discriminating controls

- Honest guest execution and an actual proof of the reduction accept.
- Changes to each input point/value, terminal point/value, messages and full
  field limbs reject at the guest or final native check as appropriate.
- Missing, reordered or substituted inherited families reject.
- Changing a child public-input record while retaining its original proof
  rejects; output-record changes do not preserve the approved root statement.
- False input claims with unchanged honest sumcheck messages fail a constrained
  sumcheck identity, rather than merely a native witness-generator precheck.
- A deliberately inconsistent child proof can be constructed using the old
  test-only same-seed/different-bytecode technique. A reduction made against the
  wrong table may produce a valid outer proof under its dishonest statement,
  but a receiver using the true approved table must reject the final claim.
- Carry that dishonest inherited claim through a second wrapper to exercise
  recursive inheritance rather than only a first-level reduction.
- A fresh public-only receiver needs the root, intended records, approved
  programs and reduced claims, without child proof files or signature advice.

These are integration and constraint checks. They do not establish complete
soundness of the compiler, Keccak argument, PCS or Fiat-Shamir transformation.
