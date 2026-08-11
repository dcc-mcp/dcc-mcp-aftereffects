from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry

from dcc_mcp_aftereffects.operations import official_dom


@skill_entry
def main(**kwargs):
    return action_result("After Effects official DOM operation completed.", official_dom, **kwargs)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
