# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
  The `Mac` and `MacInit` signatures in particular are shared by every MAC
  crate built on `tc_macs`.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs are short and written for crates.io: the badge block, a
  sentence or two on what the crate is, the "Types", "Traits" and "Features"
  lists, a usage example of ten lines or fewer, a short security note and the
  license. Behaviour belongs in the rustdoc, and validation and release
  commands in the root README.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std` and contains no `unsafe` code, which each crate root forbids.

The default build of `tc_macs` carries only the contracts, their errors and the
re-exported key containers, so that a MAC crate such as `tc_poly1305` depends
on nothing more; it depends on `tc_block_cipher` and `tc_zeroize`. Each MAC is
behind its own default-off feature, which adds only what that MAC needs:
`cbc-mac` and `cfb-mac` add `tc_block_modes` and `tc_block_padding`, `cmac`
adds nothing, `gmac` adds `tc_aead_cipher`, whose GCM carries GMAC, and
`tc_block_modes`, and `hmac` adds `tc_digest`. The default-off `alloc` feature
adds `KeyOwned` and, for each MAC enabled, the form that sizes its buffers at
run time (`CbcMac`, `PaddedCbcMac`, `CfbMac`, `PaddedCfbMac`, `Cmac` and
`Hmac`), gated on both features; the `Fixed` forms keep their buffers inline.
`alloc` enables features of existing dependencies and adds none. `tc_poly1305`
has no feature, never allocates, and depends on the default build of `tc_macs`
and on `tc_zeroize`. CI enforces each of these dependency sets with
`cargo tree` on the `wasm32-unknown-unknown`, `aarch64-unknown-none` and x86
targets, and runs Clippy and rustdoc on each `tc_macs` feature alone, with and
without `alloc`, so that no MAC silently relies on another's items. A new MAC in
`tc_macs` gets its own feature in the same way: the module and its re-exports
gated in `lib.rs`, its test file opening with `#![cfg(feature = "...")]`, an
entry in the README's "Features" list, and the CI loops and dependency checks.

`tc_macs` owns the `Mac` and `MacInit` contracts, the Rust form of Bouncy
Castle's `IMac`; MAC crates such as `tc_poly1305` implement them rather than
defining their own, and report `InitError` and `MacError`. Those errors wrap
the primitive's error, and their `Display` describes only their own layer,
leaving the primitive's error to `source`. MACs name themselves through
`Display`, as Bouncy Castle's `AlgorithmName` does, except that CMAC writes
`<cipher>/CMAC`, since Bouncy Castle's name is that of its inner CBC mode and
collides with CBC-MAC's. Each MAC follows its Bouncy Castle class, default tag
sizes included, with two deliberate exceptions: CBC-MAC and CFB-MAC require an
IV of exactly one block, and `Poly1305::do_final` consumes the one-time key.
Every `do_final` checks the output length before touching any state, so a
short buffer leaves the message in place; keep that order. A failed `init`
leaves the MAC uninitialized, so it never goes on under the previous key.

Every MAC in `tc_macs` is constant time exactly when the cipher or digest it
wraps is, and `Poly1305` is constant time; lengths are public.
`tests/documentation.rs` in each crate requires every public type and method,
and every trait method a MAC implements, to say which, and matches the phrase
within one line, so never wrap a line between "constant" or "variable" and
"time". The scanned file list there must grow with the crate. Keep the timing
contract of each item stated in its doc comment.

Every MAC wipes its key material and message-derived state on drop: the
`tc_macs` cores hold their buffers in `Zeroizing`, and `Poly1305` wipes its
fields in `Drop`. A new field that holds either must be wiped too. The wrapped
cipher, mode or digest wipes its own state when its type does, which the
documentation states rather than promises; copies on the stack, in registers or
left behind by moves are a documented limitation, not wiped per block.

Rust 1.85 is guaranteed for every build in the workspace, tests included,
because every dependency and dev-dependency is a first-party `tc_*` crate that
requires 1.85 as well. The MSRV job therefore runs `cargo test` on 1.85 with
no feature and with all of them. APIs stabilized after 1.85, such as `<[T]>::as_chunks`
(1.88) and `is_multiple_of` (1.87), are rejected in library code by clippy's
`incompatible_msrv` lint, which reads the inherited `rust-version`, but clippy
lets them through in tests, where only the MSRV job catches them; the
incubator's copy of the Poly1305 tests used `as_chunks`. `.cargo/config.toml`
sets `incompatible-rust-versions = "allow"` so `Cargo.lock` tracks the latest
releases. Adding any third-party dependency or dev-dependency hands part of
the 1.85 guarantee to that crate; raise it before doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans; that includes links from one MAC to another behind a different
feature, such as CBC-MAC's pointer to `FixedCmac`. The crate-level example
needs the `cmac` and `hmac` features and is gated on them inside the doctest.
An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in `tc_macs/README.md`,
"Types" in `tc_poly1305/README.md` — and in the changelog, not only in the
code. Known-answer vectors cite their source: an RFC, a NIST publication, or
the Bouncy Castle test they come from.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
