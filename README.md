# G-Man - Universal Credential Manager

![Check](https://github.com/Dark-Alex-17/gman/actions/workflows/check.yml/badge.svg)
![Test](https://github.com/Dark-Alex-17/gman/actions/workflows/test.yml/badge.svg)
![LOC](https://tokei.rs/b1/github/Dark-Alex-17/gman?category=code)
[![crates.io link](https://img.shields.io/crates/v/gman.svg)](https://crates.io/crates/gman)
![Release](https://img.shields.io/github/v/release/Dark-Alex-17/gman?color=%23c694ff)
![Crate.io downloads](https://img.shields.io/crates/d/gman?label=Crate%20downloads)
[![GitHub Downloads](https://img.shields.io/github/downloads/Dark-Alex-17/gman/total.svg?label=GitHub%20downloads)](https://github.com/Dark-Alex-17/gman/releases)

`gman` is a command-line tool for managing and injecting secrets for your scripts, automations, and applications.
It provides a single, secure interface to store, retrieve, and inject secrets so you can stop hand-rolling config
files or sprinkling environment variables everywhere.

## Overview

`gman` acts as a universal wrapper for any command that needs credentials. Store your secrets—API tokens, passwords,
certs—with a provider, then either fetch them directly or run your command through `gman` to inject what it needs as
environment variables, flags, or file content.

## Quick Examples: Before vs After

These examples show how `gman` reduces friction when running tools that need secrets. The run profile snippets referenced
here are shown later in this README under [Run Configurations](#run-configurations).

### AWS CLI (env vars)
**Before:**
```shell
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity
```

**After (with a run profile named `aws`):**
```shell
gman aws sts get-caller-identity
````

### Docker (flags)
**Before:**
```shell
docker run -e API_KEY=... -e DB_PASSWORD=... my/image
```

**After (with a run profile named `docker` that uses `-e` flags):**
```shell
gman docker run my/image
```
  - Pro Tip: Run `gman --dry-run docker run my/image` to preview the full command with masked values

### Config file injection
**Before:**
```shell
# Place plaintext secrets directly in configuration files (not recommended)
# Or use a tool like `envsubst` to replace placeholders; e.g.
export RADARR_API_KEY=...
export SONARR_API_KEY=...
envsubst < ~/.config/managarr/config.yml.template > ~/.config/managarr/config.yml
managarr radarr list movies
```

**After (with a run profile named `managarr` that injects files):**
```shell
# `gman` injects secret values into the file(s), runs the command, then restores the original content
gman managarr radarr list movies
```

### Example roundtrip of adding, retrieving, and using a secret
```shell
# Add a secret (value read from stdin)
echo "mySuperSecretValue" | gman add my_api_key
# Retrieve a secret
gman get my_api_key
# Use a secret in a wrapped command (with an 'aws' run profile defined)
gman aws sts get-caller-identity
```

## Features

- **Secure encryption** for stored secrets
- **Pluggable providers** (local by default; more planned)
- **Git sync for local vaults** to move secrets across machines
- **Command wrapping** to inject secrets for any program
- **Customizable run profiles** (env, flags, or files)
- **Direct secret retrieval** via `gman get ...`
- **Dry-run** to preview wrapped commands and secret injection

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Providers](#providers)
  - [Provider: `local`](#provider-local)
- [Run Configurations](#run-configurations)
  - [Environment Variable Secret Injection](#environment-variable-secret-injection)
  - [Inject Secrets via Command-Line Flags](#inject-secrets-via-command-line-flags)
  - [Inject Secrets into Files](#inject-secrets-into-files)
- [Detailed Usage](#detailed-usage)
  - [Storing and Managing Secrets](#storing-and-managing-secrets)
  - [Running Commands](#running-commands)
  - [Multiple Providers and Switching](#multiple-providers-and-switching)
- [Creator](#creator)

## Installation

### Cargo
If you have Cargo installed, then you can install `gman` from Crates.io:

```shell
cargo install gman

# If you encounter issues installing, try installing with '--locked'
cargo install --locked gman
```

### Homebrew (Mac/Linux)
To install G-Man from Homebrew, install the `gman` tap. Then you'll be able to install `gman`:

```shell
brew tap Dark-Alex-17/gman
brew install gman

# If you need to be more specific, use:
brew install Dark-Alex-17/gman/gman
```

To upgrade `gman` using Homebrew:

```shell
brew upgrade gman
```

### Chocolatey (Windows)
The G-Man Chocolatey package is located [here](https://community.chocolatey.org/packages/gman). Please note that validation
of Chocolatey packages take quite some time, and thus the package may not be available immediately after a new release.

```powershell
choco install gman

# Some newer releases may require a version number, so you can specify it like so:
choco install gman --version=0.1.0
```

To upgrade to the latest and greatest version of G-Man:
```powershell
choco upgrade gman

# To upgrade to a specific version:
choco upgrade gman --version=0.1.0
```

### Manual
Binaries are available on the [releases](https://github.com/Dark-Alex-17/gman/releases) page for the following platforms:

| Platform       | Architecture(s)            |
|----------------|----------------------------|
| macOS          | x86_64, arm64              |
| Linux GNU/MUSL | x86_64,armv6,armv7,aarch64 |
| Windows        | x86_64,aarch64             |

#### Windows Instructions
To use a binary from the releases page on Windows, do the following:

1. Download the latest [binary](https://github.com/Dark-Alex-17/gman/releases) for your OS.
2. Use 7-Zip or TarTool to unpack the Tar file.
3. Run the executable `gman.exe`!

#### Linux/MacOS Instructions
To use a binary from the releases page on Linux/MacOS, do the following:

1. Download the latest [binary](https://github.com/Dark-Alex-17/gman/releases) for your OS.
2. `cd` to the directory where you downloaded the binary.
3. Extract the binary with `tar -C /usr/local/bin -xzf gman-<arch>.tar.gz` (Note: This may require `sudo`)
4. Now you can run `gman`!

## Configuration

`gman` reads a YAML configuration file located at an OS-specific path:

### Linux
```
$HOME/.config/gman/config.yml
```

### Mac
```
$HOME/Library/Application Support/rs.gman/config.yml
```

### Windows
```
%APPDATA%/Roaming/gman/config.yml
```

### Discover paths (helpful for debugging)

You can ask `gman` where it writes its log file and where it expects the config file to live:

```shell
gman --show-log-path
gman --show-config-path
```

### Default Configuration

`gman` supports multiple providers. Select one as the default and then list provider configurations.

```yaml
---
default_provider: local
providers:
  - name: local
    type: local
    password_file: ~/.gman_password
    # Optional Git sync settings for the 'local' provider
    git_branch: main # Defaults to 'main'
    git_remote_url: null # Set to enable Git sync (SSH or HTTPS)
    git_user_name: null # Defaults to global git config user.name
    git_user_email: null # Defaults to global git config user.email
    git_executable: null # Defaults to 'git' in PATH

# List of run configurations (profiles). See below.
run_configs: []
```

## Providers
`gman` supports multiple providers for secret storage. The default provider is `local`, which stores secrets in an 
encrypted file on your filesystem. The CLI and config format are designed to be extensible so new providers can be
documented and added without breaking existing setups. The following table shows the available and planned providers:

**Key:**

| Symbol | Status    |
|--------|-----------|
| ✅      | Supported |
| 🕒     | Planned   |
| 🚫     | Won't Add |


| Provider Name                                                                                                            | Status | Configuration Docs       |  Comments                                  |
|--------------------------------------------------------------------------------------------------------------------------|--------|--------------------------|--------------------------------------------|
| `local`                                                                                                                  | ✅      | [Local](#provider-local) |                                            |
| [`aws_secrets_manager`](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)                          | 🕒     |                          |                                            |
| [`aws_ssm_parameter_store`](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_parameterstore.html) | 🕒     |                          |                                            |
| [`hashicorp_vault`](https://www.hashicorp.com/en/products/vault)                                                         | 🕒     |                          |                                            |
| [`azure_key_vault`](https://azure.microsoft.com/en-us/products/key-vault/)                                               | 🕒     |                          |                                            |
| [`gcp_secret_manager`](https://cloud.google.com/security/products/secret-manager?hl=en)                                  | 🕒     |                          |                                            |
| [`1password`](https://1password.com/)                                                                                    | 🕒     |                          |                                            |
| [`bitwarden`](https://bitwarden.com/)                                                                                    | 🕒     |                          |                                            |
| [`dashlane`](https://www.dashlane.com/)                                                                                  | 🕒     |                          | Waiting for CLI support for adding secrets |
| [`lastpass`](https://www.lastpass.com/)                                                                                  | 🕒     |                          |                                            |

### Provider: `local`

The default `local` provider stores an encrypted vault file on your filesystem. Any time you attempt to access the local 
vault (e.g., adding, retrieving, or deleting secrets), `gman` will prompt you for the password you used to encrypt the 
applicable secrets.

Similar to [Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/vault_managing_passwords.html#storing-passwords-in-files), `gman` lets you store the password in a file for convenience. This is done via the 
`password_file` configuration option. If you choose to use a password file, ensure that it is secured with appropriate 
file permissions (e.g., `chmod 600 ~/.gman_password`). The default file for the password file is `~/.gman_password`.

For use across multiple systems, `gman` can sync with a remote Git repository (requires `git` to be installed).

**Important Notes for Git Sync:**
- You **must** create the remote repository on your Git provider (e.g., GitHub) *before* attempting to sync.
- The `git_remote_url` must be in SSH or HTTPS format (e.g., `git@github.com:your-user/your-repo.git`).
- First sync behavior:
  - If the remote already has content, `gman sync` adopts the remote state and discards uncommitted local changes in the
    vault directory to avoid merge conflicts.
  - If the remote is empty, `gman sync` initializes the repository locally, creates the first commit, and pushes.

**Example `local` provider config for Git sync:**
```yaml
default_provider: local
providers:
  - name: local
    type: local
    git_branch: main
    git_remote_url: "git@github.com:my-user/gman-secrets.git"
    git_user_name: "Your Name"
    git_user_email: "your.email@example.com"
```

Repository layout and file tracking
- By default (no sync), secrets are stored in a single file: `~/.config/gman/vault.yml`.
- After configuring a remote and running `gman sync` for the first time:
  - A dedicated repository directory is created under the config dir, derived from the remote name, e.g. `~/.config/gman/.vault` or `~/.config/gman/.test-vault`.
  - The existing `vault.yml` is moved into that directory as `~/.config/gman/.<repo-name>/vault.yml`.
  - Only `vault.yml` is tracked and committed in that repository; other files in the config directory are ignored.
- With multiple `local` providers each pointing at different remotes, each gets its own `.repo-name` directory, so you can switch between isolated sets of secrets.

Security and encryption basics
- Client-side encryption: Secrets are encrypted before being written to disk. The local provider uses Argon2id for key
  derivation and XChaCha20-Poly1305 (AEAD) for encryption/authentication.
- Strong defaults: A unique random salt and nonce are generated with the OS RNG for every encryption; Argon2id parameters
  are tuned for interactive usage and can evolve in future versions.
- Tamper detection: The AEAD ensures decryption fails if the password is wrong or the ciphertext is modified.
- Envelope format: The stored value encodes header, version, KDF params, and base64-encoded salt, nonce, and ciphertext
  to enable robust, portable decryption.
- Memory hygiene: Sensitive buffers are wiped after use (zeroized), and secrets are handled with types (like SecretString)
  that reduce accidental exposure through logs and debug prints. No plaintext secrets are logged.

## Run Configurations

Run configurations (or "profiles") tell `gman` how to inject secrets into a command. Three modes of secret injection are
supported:

1. [**Environment Variables** (default)](#environment-variable-secret-injection)
2. [**Command-Line Flags**](#inject-secrets-via-command-line-flags)
3. [**Files**](#inject-secrets-into-files)

When you wrap a command with `gman` and don't specify a specific run configuration via `--profile`, `gman` will look for 
a profile with a `name` matching `<command>`. If found, it injects the specified secrets. If no profile is found, `gman` 
will error out and report that it could not find the run config with that name.

You can manually specify which run configuration to use with the `--profile` flag. Again, if no profile is found with 
that name, `gman` will error out.

### Environment Variable Secret Injection

By default, secrets are injected as environment variables. The two required fields are `name` and `secrets`.

**Example:** A profile for the `aws` CLI.
```yaml
run_configs:
  - name: aws
    secrets:
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
```
When you run `gman aws ...`, `gman` will fetch these two secrets and expose them as environment variables to the `aws` 
process.

### Inject Secrets via Command-Line Flags

For applications that don't read environment variables, you can configure `gman` to pass secrets as command-line flags. 
This requires three additional fields: `flag`, `flag_position`, and `arg_format`.

- `flag`: The flag to use (e.g., `-e`).
- `flag_position`: An integer indicating where to insert the flag in the command's arguments. `1` is immediately after 
  the command name.
- `arg_format`: A string that defines how the secret is formatted. It **must** contain the placeholders `{{key}}` and 
  `{{value}}`.

**Example:** A profile for `docker run` that uses the `-e` flag.
```yaml
run_configs:
  - name: docker
    secrets:
      - MY_APP_API_KEY
      - MY_APP_DB_PASSWORD
    flag: -e
    flag_position: 2 # In 'docker run ...', the flag comes after 'run', so position 2.
    arg_format: "{{key}}={{value}}"
```
When you run `gman docker run my-image`, `gman` will execute a command similar to:
`docker run -e MY_APP_API_KEY=... -e MY_APP_DB_PASSWORD=... my-image`

### Inject Secrets into Files

For applications that require secrets to be provided via files, you can configure `gman` to automatically populate 
specified files with the secret values before executing the command, run the command, and then restore the original
content regardless of command completion status.

This just requires one additional field:

- `files`: A list of _absolute_ file paths where the secret values should be written.

**Example:** An implicit profile for [`managarr`](https://github.com/Dark-Alex-17/managarr) that injects the specified
secrets into the corresponding configuration file. More than one file can be specified, and if `gman` can't find any
specified secrets, it will leave the file unchanged.


```yaml
run_configs:
  - name: managarr
    secrets:
      - RADARR_API_KEY
      - SONARR_API_KEY
    files:
      - /home/user/.config/managarr/config.yml
```

And this is what my `managarr` configuration file looks like:

```yaml
radarr:
  - name: Radarr
    host: 192.168.0.105
    port: 7878
    api_token: '{{RADARR_API_KEY}}' # This will be replaced by gman with the actual secret value
sonarr:
  - name: Sonarr
    host: 192.168.0.105
    port: 8989
    api_token: '{{SONARR_API_KEY}}'
```

Then, all you need to do to run `managarr` with the secrets injected is:

```shell
gman managarr
```

## Detailed Usage

### Storing and Managing Secrets

- **Add a secret:**
  ```sh
  # The value is read from standard input
  echo "your-secret-value" | gman add my_api_key
  ```
  or don't provide a value to add the secret interactively:
  ```shell
  gman add my_api_key
  ```

- **Retrieve a secret:**
  ```sh
  gman get my_api_key
  ```

- **Update a secret:**
  ```sh
  echo "new-secret-value" | gman update my_api_key
  ```
  or don't provide a value to update the secret interactively:
  ```shell
  gman add my_api_key
  ```

- **List all secret names:**
  ```sh
  gman list
  ```

- **Delete a secret:**
  ```sh
  gman delete my_api_key
  ```

- **Synchronize with remote secret storage (specific to the configured `provider`):**
  ```sh
  gman sync
  ```

### Running Commands

- **Using a default profile:**
  ```sh
  # If an 'aws' profile exists, secrets are injected.
  gman aws sts get-caller-identity
  ```

- **Specifying a profile:**
  ```sh
  # Manually specify which profile to use with --profile
  gman --profile my-docker-profile docker run my-app
  ```

- **Dry Run:**
  ```sh
  # See what command would be executed without running it.
  gman --dry-run aws s3 ls
  # Output will show: aws -e AWS_ACCESS_KEY_ID=***** ... s3 ls
  ```

### Multiple Providers and Switching

You can define multiple providers—even multiple of the same type—and switch between them per command.

Example: two AWS Secrets Manager providers named `lab` and `prod`.

```yaml
default_provider: prod
providers:
  - name: lab
    type: local
    password_file: /home/user/.lab_gman_password
    git_branch: main
    git_remote_url: git@github.com:username/lab-vault.git

  - name: prod
    type: local
    password_file: /home/user/.prod_gman_password
    git_branch: main
    git_remote_url: git@github.com:username/prod-vault.git

run_configs:
  - name: aws
    secrets:
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
```

Switch providers on the fly using the provider name defined in `providers`:

```sh
# Use the default (prod)
gman aws s3 ls

# Explicitly use lab
gman --provider lab aws s3 ls

# Fetch a secret from prod
gman get my_api_key

# Fetch a secret from lab
gman --provider lab get my_api_key
```

## Creator
* [Alex Clarke](https://github.com/Dark-Alex-17)
