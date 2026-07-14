import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPTS = Path(__file__).parents[1] / "src" / "dcc_mcp_aftereffects" / "skills" / "aftereffects-project" / "scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_project_skills_use_typed_aftereffects_facade(tmp_path):
    comp = SimpleNamespace(name="Intro", width=1920, height=1080, duration=5.0)
    project = SimpleNamespace(name="Demo", item_count=1, compositions=[comp], save=mock.Mock())
    app = SimpleNamespace(project=project, active_item=comp)
    cases = (
        ("inspect_project", (), {"project_name": "Demo", "item_count": 1, "active_item": "Intro"}),
        ("list_compositions", (), {"compositions": [{"name": "Intro", "width": 1920, "height": 1080, "duration": 5.0}], "composition_count": 1}),
        ("save_project", (str(tmp_path / "intro.aep"),), {"path": str(tmp_path / "intro.aep"), "saved": True}),
    )
    for name, args, expected in cases:
        module = load_script(name)
        with mock.patch.object(module, "AfterEffects", return_value=app):
            assert getattr(module, name)(*args) == expected
    project.save.assert_called_once_with(str(tmp_path / "intro.aep"))
