# Current source export — 2026-10-26

This tree synchronizes the locally accepted Sitina runtime, including main-agent
request-body evidence, child handoff and review completion fixes. It contains
source code and configuration templates only. User sessions, model request
bodies, Keychain credentials, extension installations and local test workspaces
are not included.

Production-directory guards now resolve the real POSIX account home through
the operating system account database. Changing HOME does not remove protection
from that account's SitinaHub. Legacy tools retain their existing authorization,
marker, identity and write-fence checks.

Validation for this export:
- 12 focused protection / legacy fence tests passed in an isolated workspace.
- 10 portable-protection tests passed against this exported tree.
- Python syntax was checked for the export. This is not a claim that every
  historical acceptance program was run.
- The preceding native regression established complete child-report matching in
  the main agent's serialized model requests and successful review completion.
  Private raw evidence remains local.

Configuration differences from the existing installation:
- The example filesystem MCP is restricted to the configured Sitina root.
- The example Obsidian vault list is empty until explicitly configured.
- Credential-bearing .env files, runtime data and backup files are excluded.

Personal absolute paths in documentation and historical JSON were redacted.
Hashes and historical acceptance records in those redacted documents must not
be treated as current verifiable evidence. Historical test scripts still need
their original input datasets and approvals; replacing account paths does not
supply those inputs or authorize a production operation.

This update does not rewrite Git history or change repository visibility.

