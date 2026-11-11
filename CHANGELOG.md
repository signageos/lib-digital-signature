# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

Entries should be short and human-readable; for longer entries, use an indented list.

`Changed` and `Removed` entries should be used only for breaking changes to the outward-facing API.

## [Unreleased]

## [3.2.1] - 2026-11-11
### Fixed
- The ES module build now loads natively in Node.js.
- (public) Signed messages, including requests without a body, are no longer intermittently rejected by the verifier.

## [3.2.0] - 2025-06-19
### Added
- Initial release of the `digital-signature` library.
