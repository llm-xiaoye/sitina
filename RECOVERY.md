# Restore a clean Sitina installation

This private repository is the recovery source for a clean Sitina software
installation. It contains the application code, policies, prompts, schemas,
tests, and non-secret Provider templates.

It intentionally does **not** contain local credentials, macOS Keychain
material, Journal/CAS history, conversations, generated artifacts, sessions,
or caches. Those are runtime state, not a clean installation, and may contain
sensitive information.

## Restore

```bash
cd "$HOME"
git clone https://github.com/llm-xiaoye/sitina.git SitinaHub
cd SitinaHub
./scripts/restore-clean-install.sh --install-deps
```

The script verifies Python 3.12, installs the locked dependencies when
requested, creates empty runtime directories, and performs a Provider-free
CLI smoke check.

Create a local Provider profile from a checked-in example:

```bash
cp profiles/deepseek.env.example profiles/deepseek.env
chmod 600 profiles/deepseek.env
```

Edit the endpoint and model, then put the raw token in macOS Keychain and keep
only its `keychain://` reference in the profile. See `profiles/README.md`.

Optionally expose the command on `PATH`:

```bash
mkdir -p "$HOME/bin"
ln -sfn "$HOME/SitinaHub/bin/sitina" "$HOME/bin/sitina"
```

Verify without making a Provider request:

```bash
SITINA_HOME="$HOME/SitinaHub" "$HOME/SitinaHub/bin/sitina" --help
SITINA_HOME="$HOME/SitinaHub" "$HOME/SitinaHub/bin/sitina" provider status
```

## What this recovery does not restore

- Previous Journal/CAS history or completed runs.
- Old conversations, evidence, outputs, or artifacts.
- Provider tokens or Sitina encryption/signing keys.
- Machine-specific paths such as an Obsidian vault location.

That exclusion is deliberate: the result is a clean installation. Historical
state requires a separate encrypted backup with its matching Keychain
material and is not stored in Git.
