from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry

from dcc_mcp_aftereffects.operations import configure_output_module


@skill_entry
def main(**kwargs):
    return action_result(
        "After Effects output module configured.", configure_output_module, **kwargs
    )


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
