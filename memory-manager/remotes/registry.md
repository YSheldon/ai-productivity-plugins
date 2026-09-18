# Cloud backup remotes (记忆管家)

Business-unrelated nest lives in this repo (`YSheldon/ai-productivity-plugins`).
Fleet / product bot memories stay on their own remotes.

| id | purpose | git remote | local workdir | notes |
|----|---------|------------|---------------|-------|
| nest | 记忆管家自身窝：self meta、多备份点登记、编排约定 | https://github.com/YSheldon/ai-productivity-plugins | `/workspace/ai-productivity-plugins` | **public** — no secrets / no private fleet dumps |
| fleet-ai-bots | 业务舰队记忆灾备（registry + bots/*/MEMORY + chats） | https://github.com/YSheldon/AI-Bots | `/workspace/memory-manager` | **private** |

## Rules
- Never commit tokens/cookies/secrets to any remote.
- Nest remote is public: keep self backups operational but scrub private bot rosters, internal paths that leak customer work, and chat dumps that belong on private remotes.
- Fleet dumps (MEMORY, redacted chats) go only to private remotes listed above.
- Manual: 「存档」→ fleet remote(s); 「备份自己」→ nest; 「导入」defaults to named remote or asks.

## Last verified
- 2026-09-18 PT: GH_TOKEN Contents R/W confirmed for both remotes via API + git ls-remote.
