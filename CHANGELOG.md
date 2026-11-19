# Changelog

## [0.4.0](https://github.com/agenthooksprotocol/adapter-openclaw/compare/v0.3.0...v0.4.0) (2026-11-19)


### ⚠ BREAKING CHANGES

* **oauth:** grants are keyed by the configured client identity in agenthooksprotocol 0.15.0, so stored grants are not found and each backend needs one new sign-in. The Gateway's live --port is no longer recorded: set gateway.port (or OPENCLAW_GATEWAY_PORT, or publicUrl) to where it runs.

### Bug Fixes

* **oauth:** sign in from the CLI on agenthooksprotocol 0.16.0 ([#6](https://github.com/agenthooksprotocol/adapter-openclaw/issues/6)) ([379f54f](https://github.com/agenthooksprotocol/adapter-openclaw/commit/379f54fa9b0210a7c0f510b6b12c3921b3ce2210))

## [0.3.0](https://github.com/agenthooksprotocol/adapter-openclaw/compare/v0.2.0...v0.3.0) (2026-11-18)


### Features

* OAuth browser sign-in per backend ([#4](https://github.com/agenthooksprotocol/adapter-openclaw/issues/4)) ([f36971f](https://github.com/agenthooksprotocol/adapter-openclaw/commit/f36971f6e82e23e79c60d8ad0ec2c54457793aa9))

## [0.2.0](https://github.com/agenthooksprotocol/adapter-openclaw/compare/v0.1.0...v0.2.0) (2026-11-17)


### Features

* upgrade to agenthooksprotocol 0.12.0 ([#2](https://github.com/agenthooksprotocol/adapter-openclaw/issues/2)) ([628dec7](https://github.com/agenthooksprotocol/adapter-openclaw/commit/628dec7ec68d69801fbd340ae357572ca68fe1a6))
