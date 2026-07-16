# dcc-mcp-aftereffects

MCP adapter for Adobe After Effects, built on the shared `adobepy` broker, CEP bridge, and typed facade.

```bash
pip install dcc-mcp-aftereffects
```

Install the shared bridge with `adobepy install-bridge after-effects --dest <extension-dir> --token <token>`, open it in After Effects, then start the adapter. Each adapter instance uses an OS-assigned port and registers it for CLI discovery. Connect through the stable gateway at `http://127.0.0.1:9765/mcp`; set `DCC_MCP_AFTEREFFECTS_PORT` only when a fixed direct endpoint is required.

Set `ADOBEPY_TOKEN` to the same non-default token used when installing the bridge.

## Tools

- `aftereffects-project.inspect_project`
- `aftereffects-project.list_compositions`
- `aftereffects-project.save_project`
