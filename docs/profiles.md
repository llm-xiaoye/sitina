# Sitina Provider Profiles

Sitina role mapping lives in:

```text
~/SitinaHub/config/roles.env
```

Provider credentials and model IDs live in:

```text
~/SitinaHub/profiles/*.env
```

Each profile is loaded by role name. For example:

```bash
export SITINA_ROLE_CONTROLLER_PROFILE="gpt"
```

loads:

```text
~/SitinaHub/profiles/gpt.env
```

Profile files must be mode `600` and should export:

```bash
export ANTHROPIC_BASE_URL="..."
export ANTHROPIC_AUTH_TOKEN="..."
export ANTHROPIC_MODEL="..."
```

Do not print or commit real profile files.
