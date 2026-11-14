The four panels are two totals and two breakdowns. They are not four costs to add together.

Here, a *receipt* means the root STARK plus any auxiliary data required to verify it, such as Raccoon-G's witness bindings or FORS's remaining polynomial claims.

Conceptually, the receiver performs three kinds of work:

$$
\begin{aligned}
T_{\text{first use}} &\approx T_{\text{setup}}+T_{\text{public processing}}+T_{\text{proof checks}},\\
T_{\text{prepared}} &\approx T_{\text{public processing}}+T_{\text{proof checks}}.
\end{aligned}
$$

The panels show these costs from different perspectives:

| Panel | What it measures | Why it is useful |
|---|---|---|
| Top left: Including program setup | Prepare the approved verifier programs and tables, derive the expected public claims, and verify the receipt. | Shows the first-use cost. |
| Top right: Prepared programs and tables | Public processing and receipt verification after program preparation. | Shows the cost when that preparation has already been done. |
| Bottom left: Native tree verification | Complete cryptographic verification, with the expected public claims already prepared. | Isolates the cost of checking the proof. |
| Bottom right: All original key/message pairs | Process the intended public keys and messages and derive the exact claims the proof must authenticate. | Isolates the cost of linking the proof to the intended transactions. |

**Program setup** means loading or compiling the approved programs and preparing verification tables and recursion circuits. It does not mean a trusted setup ceremony. FORS has substantially more preparation work in this implementation, explaining much of its high top-left curve.

**Public processing** answers: "Does this proof concern the transactions I intend to accept?"

The receiver processes every original public-key/message pair, constructs the expected leaf commitments, and accounts for ordering and padding. For Raccoon-G, it constructs five part claims per signature using the same supplied $D$.

This work is essential. A cryptographically valid proof for a different set of transactions would not authorize the intended transactions. Public processing does not verify the signatures again; it constructs the statement that the STARK must prove.

**Proof verification** answers: "Is that statement correctly proved?"

The bottom-left panel includes the root STARK and all remaining verifier obligations. It is not just a check of the root transcript.

For RISC-V, complete `Tree::verify` checks the recursive proof and settles its remaining program, memory and circuit claims. For FORS, it checks the root STARK and evaluates the remaining reduced program claims. At 100 signatures, FORS has five such final evaluations. Neither path requires the original signatures or child proof files.
