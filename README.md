# gman
A universal credential management CLI with a unified interface for all your secret providers.

`gman` provides a single, consistent set of commands to manage secrets, whether they are stored in a secure local vault or any other supported provider. Switch between providers on the fly, script interactions with JSON output, and manage your secrets with ease.

## Features

- **Secure Local Storage**: Out-of-the-box support for a local vault (`~/.config/gman/vault.yml`) with strong encryption using **Argon2id** for key derivation and **XChaCha20-Poly1305** for authenticated encryption.
- **Unified Interface**: A consistent command set (`add`, `get`, `list`, etc.) for every supported provider.
- **Provider Selection**: Explicitly choose a provider for a command using the `--provider` flag.
- **Flexible Output**: Get secrets in plaintext for scripting, structured `json` for applications, or human-readable text.
- **Password Management**: For local secret storage: securely prompts for the vault password. For automation, a password can be supplied via a `~/.gman_password` file, similar to Ansible Vault.
- **Shell Completions**: Generate completion scripts for Bash, Zsh, Fish, and other shells.
- **Standardized Naming**: Secret names are automatically converted to `snake_case` to ensure consistency.

## Installation

Ensure you have Rust and Cargo installed. Then, clone the repository and install the binary:

```sh
git clone https://github.com/Dark-Alex-17/gman.git
cd gman
cargo install --path .
```

## Configuration

`gman` is configured through a YAML file located at `~/.config/gman/config.yml`.

A default configuration is created automatically. Here is an example:

```yaml
# ~/.config/gman/config.yml
---
provider: local
password_file: null # Can be set to a path like /home/user/.gman_password
```

### Vault File

For the `local` provider, secrets are stored in an encrypted vault file at `~/.config/gman/vault.yml`. This file should not be edited manually.

### Password File

To avoid being prompted for a password with every command, you can create a file at `~/.gman_password` containing your vault password. `gman` will automatically detect and use this file if it exists.

```sh
# Create the password file with the correct permissions
echo "your-super-secret-password" > ~/.gman_password
chmod 600 ~/.gman_password
```

## Usage

`gman` uses simple commands to manage secrets. Secret values are passed via `stdin`.

### Commands

**1. Add a Secret**

To add a new secret, use the `add` command. You will be prompted to enter the secret value, followed by `Ctrl-D` to save.

```sh
gman add my_api_key
```
```
Enter the text to encrypt, then press Ctrl-D twice to finish input
this-is-my-secret-api-key
^D
✓ Secret 'my_api_key' added to the vault.
```

You can also pipe the value directly:
```sh
echo "this-is-my-secret-api-key" | gman add my_api_key
```

**2. Get a Secret**

Retrieve a secret's plaintext value with the `get` command.

```sh
gman get my_api_key
```
```
this-is-my-secret-api-key
```

**3. Get a Secret as JSON**

Use the `--output json` flag to get the secret in a structured format.

```sh
gman get my_api_key --output json
```
```
{
  "my_api_key": "this-is-my-secret-api-key"
}
```

**4. List Secrets**

List the names of all secrets in the vault.

```sh
gman list
```
```
Secrets in the vault:
- my_api_key
- another_secret
```

**5. Update a Secret**

Update an existing secret's value.

```sh
echo "new-secret-value" | gman update my_api_key
```
```
✓ Secret 'my_api_key' updated in the vault.
```

**6. Delete a Secret**

Remove a secret from the vault.

```sh
gman delete my_api_key
```
```
✓ Secret 'my_api_key' deleted from the vault.
```

**7. Generate Shell Completions**

Create a completion script for your shell to enable auto-complete for commands and arguments.

```sh
# For Bash
gman completions bash > /etc/bash_completion.d/gman

# For Zsh
gman completions zsh > /usr/local/share/zsh/site-functions/_gman
```

## Creator
* [Alex Clarke](https://github.com/Dark-Alex-17)