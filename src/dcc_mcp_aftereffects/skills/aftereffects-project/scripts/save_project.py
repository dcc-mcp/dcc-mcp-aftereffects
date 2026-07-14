from dcc_mcp_core.skill import skill_entry, skill_success

from dcc_mcp_aftereffects.bridge import call_bridge


@skill_entry
def main(path: str, **_kwargs):
    return skill_success(
        "After Effects project saved.",
        **call_bridge("DCC_MCP_AFTEREFFECTS", "save_project", {"path": path}),
    )


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
