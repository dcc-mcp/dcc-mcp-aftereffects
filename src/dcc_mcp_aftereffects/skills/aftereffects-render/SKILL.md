---
name: aftereffects-render
description: Inspect, queue, configure, and control After Effects render queue items and output modules through typed adobepy facades.
license: MIT
compatibility: "After Effects CEP/ExtendScript; dcc-mcp-core 0.19+"
allowed-tools: Python
metadata:
  dcc-mcp:
    dcc: aftereffects
    version: "0.1.0"
    layer: domain
    stage: render
    search-hint: "after effects render queue output module template media encoder"
    tags: "adobe,aftereffects,render,output"
    tools: tools.yaml
---

# After Effects Render Queue

Inspect the queue before changing templates or output paths. Rendering and AME
queue operations may block and should be invoked only after outputs are set.
