# Lark CLI Codex Plugin

Packaged and maintained by Sheldon.

This plugin packages the existing Feishu/Lark `lark-*` skills as a local Codex plugin.
It does not add a separate MCP wrapper or reimplement Lark OpenAPI calls. The skills continue
to use the user's installed `lark-cli` command and the established Feishu workflows.

## Requirements

- A working Lark/Feishu CLI installation, usually `lark-cli`, `lark-cli.cmd`, or `@larksuite/cli`.
- Any required CLI authentication already configured by the user.
- The bundled skills under `skills/lark-*`.

## Marketplace Entry

This plugin is registered by the repository marketplace file:

```text
.agents/plugins/marketplace.json
```

When this repository is opened in Codex App, it appears as `飞书 / Lark CLI` in the `AI 生产力插件集` marketplace.

## Configuration

Most installations need no plugin-side config. The skills call `lark-cli` directly and follow
the shared rules in `skills/lark-shared/SKILL.md`.

If the host uses a non-standard CLI location, fix the system `PATH` or use the same local wrapper
strategy already documented in your environment. For example:

```bash
where lark-cli
lark-cli --version
```

## Included Skill Areas

The plugin bundles the existing skill directories named `lark-*`, including shared auth rules,
Docs/Wiki/Drive, Sheets/Base, Calendar, IM/Mail, Approval, Tasks, Minutes/VC, Whiteboard, Apps,
OpenAPI exploration, and workflow skills.

## Safety Notes

- Do not paste app secrets or access tokens into chat.
- Read `lark-shared` before auth, permission, identity, or high-risk write work.
- Use the operation-specific skill references before unfamiliar `lark-cli` commands.
- For file uploads or external publication, name the local file and destination before running.
