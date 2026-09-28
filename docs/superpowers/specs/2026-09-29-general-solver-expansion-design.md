# General solver expansion

## Goal

Increase confirmed flag recovery on unfamiliar CTF files by exposing the full
useful capability of already installed non-LLM solvers before adding new
task-specific code.

## Solver tiers

The default path remains bounded and fast. `ico-solve --aggressive` adds an
opt-in second tier after the cheap evidence pass:

- Ciphey runs on bounded text and encoded blobs, preserving its transform
  chain and accepted output.
- RsaCtfTool runs its complete local attack selection when an RSA public key,
  modulus/ciphertext transcript or PEM key is present.
- Binary Refinery receives a bounded transform-search plan beyond the six
  existing direct encoding units; each derived artifact re-enters the normal
  type-aware solver queue.
- angr receives expanded but explicit limits for local ELF checker binaries;
  it records unresolved symbolic states as evidence rather than guessing a
  flag.
- FeatherDuster is optional. When installed, it classifies suspicious crypto
  evidence and provides route hints; it never fabricates plaintext.

## Activation and limits

`--aggressive` is opt-in and has independent timeout, memory, byte and derived
artifact limits. A task may exhaust its aggressive budget without blocking
other tasks. No result is selected merely because a third-party tool printed a
string: the existing flag matcher and provenance rules still apply.

## Data flow

1. Classify the input and collect cheap structural evidence.
2. Select aggressive tools by preconditions: text/encoding, RSA structures,
   native checker, or crypto-cipher evidence.
3. Run the selected tool with an isolated runtime and bounded subprocess.
4. Store command, stderr/stdout hashes, artifacts and transform chain.
5. Reprocess derived files through universal solvers and rank only flag-shaped
   values from recorded output.

## Tests

Tests cover command selection and negative preconditions. Fixture outputs
exercise candidate extraction, transform requeueing, timeout behaviour and
the fact that ordinary `ico-solve` does not invoke aggressive commands.
