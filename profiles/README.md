# Sitina Provider Profiles

Provider profile files contain only non-secret configuration and a macOS Keychain reference:

```bash
export ANTHROPIC_BASE_URL="https://provider.example/anthropic"
export ANTHROPIC_AUTH_TOKEN_REF="keychain://com.sitina.provider/profile-name"
export ANTHROPIC_MODEL="model-id"
```

Each real profile must be mode `600`. `ANTHROPIC_AUTH_TOKEN` is forbidden in profile files.
The Keychain item stores the raw UTF-8 Provider token under the referenced service/account.
Credential provisioning and rotation are operator actions; Sitina never migrates or overwrites a credential automatically.
