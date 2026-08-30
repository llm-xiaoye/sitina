# Sitina Provider Profiles

Provider profiles are local operator configuration. Real `profiles/*.env`
files are intentionally ignored by Git because they may refer to credentials
or contain machine-specific endpoints.

Start from one of the checked-in `.env.example` files, copy it to
`profiles/<name>.env`, edit the non-secret values, and set mode `600`:

```bash
cp profiles/deepseek.env.example profiles/deepseek.env
chmod 600 profiles/deepseek.env
```

Raw tokens must not be written to a profile. Store the token in macOS
Keychain and keep only a reference in the file:

```bash
export ANTHROPIC_BASE_URL="https://provider.example/anthropic"
export ANTHROPIC_AUTH_TOKEN_REF="keychain://com.sitina.provider/profile-name"
export ANTHROPIC_MODEL="model-id"
```

DeepSeek is the current test profile, not a hard-coded platform dependency.
The same profile contract supports OpenAI-, Anthropic-, and other compatible
providers by changing the endpoint, model, and role mapping.
