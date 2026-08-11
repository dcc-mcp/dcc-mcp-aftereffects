from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry

from dcc_mcp_aftereffects.operations import list_project_items


@skill_entry
def main(**kwargs):
    return action_result("After Effects project items listed.", list_project_items, **kwargs)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
