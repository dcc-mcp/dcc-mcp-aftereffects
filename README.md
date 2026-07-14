# dcc-mcp-aftereffects

MCP adapter for Adobe After Effects. It uses a bundled CEP panel and typed ExtendScript handlers over a localhost-only bridge.

```bash
pip install dcc-mcp-aftereffects
```

Install the shipped `dcc_mcp_aftereffects/aftereffects_cep` extension, open its panel in After Effects, and start `dcc-mcp-aftereffects` through the normal MCP launcher. The MCP endpoint defaults to `http://127.0.0.1:8765/mcp`.

Set the same non-default `DCC_MCP_AFTEREFFECTS_BRIDGE_TOKEN` in the adapter environment and CEP panel before production use.

## Tools

- `aftereffects-project.inspect_project`
- `aftereffects-project.list_compositions`
- `aftereffects-project.save_project`
