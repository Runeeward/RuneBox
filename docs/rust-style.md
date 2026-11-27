# Rust style

We follow the [Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html) for general Rust practice. Its Chromium, Android and Fuchsia rules don't apply. The rules below are the ones we enforce. Most are workspace lints in `Cargo.toml`, and CI runs `cargo clippy --workspace --all-targets -- -D warnings`.

## Errors and panics

- Production code doesn't call `unwrap` or `expect` (`clippy::unwrap_used`, `clippy::expect_used`). Return an error instead.
- Where a panic is the only sound response (the OS random source failing, or a constant regex), use `#[expect(clippy::expect_used, reason = "...")]` on that item and add a `# Panics` section to its docs.
- Tests may unwrap and expect (`clippy.toml`). Integration-test files opt out with a file-level `#![allow(clippy::expect_used, reason = "tests")]`.
- `catch_unwind` is only for third-party code that panics on bad input, and the result must fail closed (see the CEL and Rego engines in `runebox-policy`). This needs `panic = "unwind"`, the default, in every profile.

## Unsafe

- `unsafe_code` is denied workspace-wide. A crate that needs it allows it on the smallest item possible.
- Every `unsafe` block has a `// SAFETY:` comment that says why the call is sound (`clippy::undocumented_unsafe_blocks`).

## Imports, docs and files

- No glob imports, except `use super::*` in test modules and a test crate's own support module.
- Public items in library crates have doc comments.
- Split a file once it gets hard to navigate (roughly 1,500 lines), when you're already changing it.

## Dependencies

`cargo deny check` (`deny.toml`) and `cargo audit` run in CI. New licenses need an entry in `deny.toml`, scoped to the crate when only one crate needs it.
