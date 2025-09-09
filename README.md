# gman - Universal Credential Manager

`gman` is a command-line tool designed to streamline credential and secret management for your scripts, automations, and 
applications. It provides a single, secure interface to store, retrieve, and inject secrets, eliminating the need to 
juggle different methods like configuration files or environment variables for each tool.

## Overview

The core philosophy of `gman` is to act as a universal wrapper for any command that requires credentials. You can store 
your secrets—like API tokens, passwords, or certificates—in an encrypted vault backed by various providers. Then, you 
can either fetch them directly or, more powerfully, execute commands through `gman`, which securely injects the 
necessary secrets as environment variables or command-line flags.

## Features

- **Secure, Encrypted Storage**: All secrets are stored in an encrypted state using strong cryptography.
- **Pluggable Providers**: Supports different backends for secret storage. The default is a local file-based system.
- **Git Synchronization**: The `local` provider can synchronize your encrypted secrets across multiple systems using a 
  private Git repository.
- **Seamless Command Wrapping**: Run any command through `gman` to automatically provide it with the secrets it needs 
  (e.g., `gman aws s3 ls`).
- **Customizable Run Profiles**: Define how secrets are passed to commands, either as environment variables (default) or 
  as specific command-line flags.
- **Secret Name Standardization**: Enforces `snake_case` for all secret names to ensure consistency.
- **Direct Secret Access**: Retrieve plaintext secrets directly when needed (e.g., `gman get my_api_key`).
- **Dry Run Mode**: Preview the command and the secrets that will be injected without actually executing it using the 
  `--dry-run` flag.

## Installation

### Cargo
If you have Cargo installed, then you can install gman from Crates.io:

```shell
cargo install gman

# If you encounter issues installing, try installing with '--locked'
cargo install --locked gman
```

## Configuration

`gman` is configured via a YAML file located somewhere different for each OS:

### Linux
```
$HOME/.config/gman/config.yml
```

### Mac
```
$HOME/Library/Application Support/gman/config.yml
```

### Windows
```
%APPDATA%/Roaming/gman/config.yml
```

### Default Configuration

```yaml
---
provider: local
password_file: ~/.gman_password

# Optional Git sync settings for the 'local' provider
git_branch: null # Defaults to 'main'
git_remote_url: null # Required for Git sync
git_user_name: null # Defaults to global git config user.name
git_user_email: null # Defaults to global git config user.email
git_executable: null # Defaults to 'git' in PATH
run_configs: null # List of run configurations (profiles)
```

### Provider: `local`

The default `local` provider stores an encrypted vault file on your filesystem. For use across multiple systems, it can 
sync with a remote Git repository.

**Important Notes for Git Sync:**
- You **must** create the remote repository on your Git provider (e.g., GitHub) *before* attempting to sync.
- The `git_remote_url` must be in SSH or HTTPS format (e.g., `git@github.com:your-user/your-repo.git`).

**Example `local` provider config for Git sync:**
```yaml
provider: local
git_branch: main
git_remote_url: "git@github.com:my-user/gman-secrets.git"
git_user_name: "Your Name"
git_user_email: "your.email@example.com"
```

### Run Configurations

Run configurations (or "profiles") tell `gman` how to inject secrets into a command. When you run `gman <command>`, it 
looks for a profile with a `name` matching `<command>`. If found, it injects the specified secrets. If no profile is 
found, `gman` will error out and report that it could not find the run config with that name.

#### Important: Secret names are always injected in `UPPER_SNAKE_CASE` format.

#### Basic Run Config (Environment Variables)

By default, secrets are injected as environment variables. The two required fields are `name` and `secrets`.

**Example:** A profile for the `aws` CLI.
```yaml
run_configs:
  - name: aws
    secrets:
      - aws_access_key_id
      - aws_secret_access_key
```
When you run `gman aws ...`, `gman` will fetch these two secrets and expose them as environment variables to the `aws` 
process.

#### Advanced Run Config (Command-Line Flags)

For applications that don't read environment variables, you can configure `gman` to pass secrets as command-line flags. 
This requires three additional fields: `flag`, `flag_position`, and `arg_format`.

- `flag`: The flag to use (e.g., `-e`).
- `flag_position`: An integer indicating where to insert the flag in the command's arguments. `1` is immediately after 
  the command name.
- `arg_format`: A string that defines how the secret is formatted. It **must** contain the placeholders `{key}` and 
  `{value}`.

**Example:** A profile for `docker run` that uses the `-e` flag.
```yaml
run_configs:
  - name: docker
    secrets:
      - my_app_api_key
      - my_app_db_password
    flag: -e
    flag_position: 2 # In 'docker run ...', the flag comes after 'run', so position 2.
    arg_format: "{key}={value}"
```
When you run `gman docker run my-image`, `gman` will execute a command similar to:
`docker run -e MY_APP_API_KEY=... -e MY_APP_DB_PASSWORD=... my-image`

## Usage

### Storing and Managing Secrets

All secret names are automatically converted to `snake_case`.

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

## Creator
* [Alex Clarke](https://github.com/Dark-Alex-17)