# Agent Mandate CLI

Install Agent Mandate as a remote MCP server in the agent clients already on
your machine. The installer writes no provider credential or bearer token to a
client configuration; authentication stays in each client's browser OAuth
flow.

```sh
npx @agent-mandate/cli protect github \
  --endpoint https://mandate.example.com/mcp
```

Supported clients: Codex, Claude Code, Cursor, VS Code, and Gemini CLI. Use
`--clients` to select an explicit subset and `--dry-run` to inspect changes.
File-backed Cursor replacement is atomic. Native client conflicts are refused
when their complete prior state cannot be restored safely.

The CLI configures mediation. Run `am doctor` to identify common direct GitHub
credential paths; only deployment isolation can support an enforcement claim.

See the [main repository](https://github.com/shabbirmur/agent-mandate) for the
self-hosted service, threat model, and security boundary.
