# Maintaining Project Documentation

[Home](../README.md) | [Catalog](plugin-catalog.md) | [Changelog](../CHANGELOG.md)

## Sources of Truth

- `.agents/plugins/marketplace.json` defines Codex availability.
- `.cursor-plugin/marketplace.json` and `.grok-plugin/marketplace.json` define client-index membership.
- `plugins/<name>/.codex-plugin/plugin.json` defines plugin version and description.
- Plugin guides define prerequisites and limits; an index entry does not prove runtime compatibility.
- Release notes summarize reviewed changes and link to source PRs.

The catalog is generated from those files. Do not hand-edit its version or
client-membership tables. Human-written highlights and upgrade notes require
review when behavior changes.

Cursor packaging is derived separately; do not replace the Codex index or its
relative `.mcp.json` paths. When packaging changes are authorized, regenerate
Cursor manifests and its Windows launch wrappers with:

```powershell
py -3 scripts/sync_cursor_plugin_manifests.py
```

Review the generated diff before committing. This command updates packaging
files; the documentation-only catalog command below does not.

```powershell
py -3 scripts/project_docs.py --write
py -3 scripts/project_docs.py --check
py -3 -m pytest -q --tb=short
```

`--write` updates only the catalog. `--check` compares the generated catalog,
checks local Markdown link targets in the showcase documents, enforces English
copy, and rejects literal private-network URLs. It does not fetch external links
or replace a full secret scan. Release CI runs it for documentation and manifest
changes.

## Release Update Checklist

1. Update the affected plugin guide and its user-facing changelog entry.
2. Refresh homepage highlights; keep them short and move older detail to the changelog.
3. Regenerate the catalog after version, description, or index changes.
4. Verify prerequisites, commands, local links, and client-specific limitations.
5. Render visuals from synthetic fixtures. Never capture real credentials, internal hosts, account identifiers, or activity logs for publication.
6. Run documentation checks and the full repository suite, then obtain independent review.
7. Publish through a focused PR. Create a tag or GitHub Release only when included in the authorized release scope.
8. Read back merged files and authorized repository metadata changes.

Keep installation, tool loading, fixture tests, authenticated acceptance, and
production results separate. Do not put a historical test count in a permanent
badge or imply universal OS support from one successful environment.

## Demo Content

The report preview uses native Markdown tables and invented records, clearly
labeled as demo data. The Mermaid flow describes credential handling; it is not
a screenshot of a real password dialog. Neither requires a local credential
operation or a browser session to regenerate. Keep labels and measurement
limitations visible, and preserve the original mail skill author's attribution.
