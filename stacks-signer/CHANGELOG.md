# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the versioning scheme outlined in the [README.md](README.md).

## [Unreleased]

## [2.5.0.0.5.1]

### Added

- Adds signerdb schema versioning (#4965)
- Added voting cli commands `generate-vote` and `verify-vote` (#4934)
- Add soritiion tracking cache (#4905)
- Push blocks to signer set and adds `/v3/blocks/upload` (#4902)

### Changed

- Fix an issue of poorly timed tenure and bitcoin blocks (#4956)
- Process pending blocks before ending tenure (#4952)
- Update rusqlite/sqlite versions (#4948)
- return last block sortition in `/v3/sortitions` (#4939)
