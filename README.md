# gman - Universal Credential Manager

`gman` is a command-line tool for managing and injecting secrets for your scripts, automations, and applications.
It provides a single, secure interface to store, retrieve, and inject secrets so you can stop hand-rolling config
files or sprinkling environment variables everywhere.

## Overview

`gman` acts as a universal wrapper for any command that needs credentials. Store your secrets—API tokens, passwords,
certs—with a provider, then either fetch them directly or run your command through `gman` to inject what it needs as
environment variables, flags, or file content.

## Features

- Secure encryption for stored secrets
- Pluggable providers (local by default; more can be added)
- Git sync for local vaults to move secrets across machines
- Command wrapping to inject secrets for any program
- Customizable run profiles (env, flags, or files)
- Consistent secret naming: input is snake_case; injected as UPPER_SNAKE_CASE
- Direct retrieval via `gman get ...`
- Dry-run to preview wrapped commands and secret injection

## Example Use Cases

### Create/Get/Delete Secrets Securely As You Need From Any Configured Provider

```shell
# Add a secret to the 'local' provider
echo "someApiKey" | gman add my_api_key

# Retrieve a secret from the 'aws_secrets_manager' provider
gman get -p aws_secrets_manager db_password

# Delete a secret from the 'local' provider
gman delete my_api_key
```

### Automatically Inject Secrets Into Any Command

```shell
# Can inject secrets as environment variables into the 'aws' CLI command
gman aws sts get-caller-identity

# Inject secrets into 'docker run' command via '-e' flags
gman docker run --rm --entrypoint env busybox | grep -i 'token'

# Inject secrets into configuration files automatically for the 'managarr' application
gman managarr
```

## Installation

### Cargo
If you have Cargo installed, then you can install gman from Crates.io:

```shell
cargo install gman

# If you encounter issues installing, try installing with '--locked'
cargo install --locked gman
```

## Configuration

`gman` reads a YAML configuration file located at an OS-specific path:

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

gman supports multiple providers. Select one as the default and then list provider configurations.

```yaml
---
default_provider: local
providers:
  - name: local
    provider: local
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

For use across multiple systems, `gman` can sync with a remote Git repository.

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
    provider: local
    git_branch: main
    git_remote_url: "git@github.com:my-user/gman-secrets.git"
    git_user_name: "Your Name"
    git_user_email: "your.email@example.com"
```

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

#### Important: Secret names are always injected in `UPPER_SNAKE_CASE` format.

### Environment Variable Secret Injection

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
      - my_app_api_key
      - my_app_db_password
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
      - radarr_api_key
      - sonarr_api_key # Remember that secret names are always converted to UPPER_SNAKE_CASE
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
    api_token: '{{sonarr_api_key}}' # gman is case-insensitive, so this will also be replaced correctly
```

Then, all you need to do to run `managarr` with the secrets injected is:

```shell
gman managarr
```

## Detailed Usage

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

### Multiple Providers and Switching

You can define multiple providers—even multiple of the same type—and switch between them per command.

Example: two AWS Secrets Manager providers named `lab` and `prod`.

```yaml
default_provider: prod
providers:
  - name: lab
    provider: aws_secrets_manager
    # Additional provider-specific settings (e.g., region, role_arn, profile)
    # region: us-east-1
    # role_arn: arn:aws:iam::111111111111:role/lab-access

  - name: prod
    provider: aws_secrets_manager
    # region: us-east-1
    # role_arn: arn:aws:iam::222222222222:role/prod-access

run_configs:
  - name: aws
    secrets:
      - aws_access_key_id
      - aws_secret_access_key
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
