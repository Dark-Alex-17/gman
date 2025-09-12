# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-09-10

### Other
- Initial test release of the `gman` project.
## v0.2.0 (2025-09-12)

### Feat

- Added two new flags to output where gman writes logs to and where it expects the config file to live

### Fix

- Made the vault file location more fault tolerant
- Attempting to maybe be a bit more explicit about config file handling to fix MacOS tests

### Refactor

- Made the creation of the log directories a bit more fault tolerant
- Renamed the provider field in a config file to type to make things a little easier to understand; also removed husky

## v0.1.0 (2025-09-11)
