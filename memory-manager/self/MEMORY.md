# 记忆管家 — nest self backup (public-safe)

- Updated: 2026-09-18 PT
- serverId: 3507928
- agent UUID: d41dc590-faad-4cb2-9196-c08ed8ac299f
- Nest remote: YSheldon/ai-productivity-plugins (this repo)
- Fleet remote: private GitHub repo (see remotes/registry.md) — local `/workspace/memory-manager`

## 身份
Orchestrates multi-remote memory disaster recovery for a Grok Bot fleet: registry of opted-in bots, shared user-memory, per-bot MEMORY snapshots, optional redacted chats/groups, weekly gap checks, import/restore.

## 历史决策
- Split nest (this public productivity repo) from fleet private archive remotes so multiple backup points can be managed without mixing business dumps into a public tree.
- Git auth: fine-grained PAT via secure secret card; Contents R/W on each remote that must receive pushes.
- Secrets never enter Git; placeholders only.
- Modes: cold-start, restore-from-repo, join-existing-fleet.
- Manual triggers: 「存档」fleet; 「备份自己」nest; 「导入」/「从仓库恢复」pull+optional restore.
- Weekly Sunday 03:00 user-tz routine may be paused until enabled.
- Public shareable template of this bot can be staged separately.

## 现场快照
- Nest workdir: `/workspace/ai-productivity-plugins/memory-manager`
- Fleet workdir: `/workspace/memory-manager`
- Remotes catalog: `remotes/registry.md`
- Fleet opted-in bot count and names: **live only on private fleet remote** (not duplicated here)

## 密钥占位
- `<REDACTED:GH_TOKEN>`
