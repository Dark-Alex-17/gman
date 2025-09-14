# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2025-09-10

### Other

## v0.0.3 (2025-09-14)

### Fix

- Revert back hacky stuff so I can test with act now
- Attempting to use pre-generated bindgens for the aws-lc-sys library
- Install openSSL differently to make this work
- Address edge case for unknown_musl targets
- Install LLVM prereqs for release flow
- Updated the release flow to install the external bindgen-cli

## v0.0.1 (2025-09-12)

### Feat

- Azure Key Vault support
- GCP Secret Manager support
- Full AWS SecretsManager support
- AWS Secrets Manager support
- Added two new flags to output where gman writes logs to and where it expects the config file to live

### Fix

- Made the vault file location more fault tolerant
- Attempting to maybe be a bit more explicit about config file handling to fix MacOS tests

### Refactor

- Refactor configuration structs directly into the provider definition to simplify validation, structs, and future extensions
- Made the creation of the log directories a bit more fault tolerant
- Renamed the provider field in a config file to type to make things a little easier to understand; also removed husky
