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


def test_motion_intro_uses_typed_template_workflow(tmp_path):
    template = tmp_path / "template.aep"
    music = tmp_path / "music.mp3"
    template.write_bytes(b"aep")
    music.write_bytes(b"mp3")
    title = SimpleNamespace(source_text=object(), set_source_text=mock.Mock(), set_keyframes=mock.Mock())
    subtitle = SimpleNamespace(source_text=object(), set_source_text=mock.Mock())
    output_module = SimpleNamespace(set_output_path=mock.Mock())
    render_item = SimpleNamespace(output_module=mock.Mock(return_value=output_module))
    composition = SimpleNamespace(
        name="Intro",
        layers=[title, subtitle],
        add_footage_layer=mock.Mock(),
        add_to_render_queue=mock.Mock(return_value=render_item),
    )
    render_queue = SimpleNamespace(render=mock.Mock())
    project = SimpleNamespace(
        compositions=[composition],
        import_file=mock.Mock(return_value=SimpleNamespace()),
        save=mock.Mock(),
        render_queue=render_queue,
    )
    app = SimpleNamespace(open_project=mock.Mock(return_value=project))
    module = load_script("create_motion_intro")
    project_path = tmp_path / "result.aep"
    output_path = tmp_path / "result.mov"
    with mock.patch.object(module, "AfterEffects", return_value=app):
        result = module.create_motion_intro(
            str(template), str(project_path), str(output_path), audio_paths=[str(music)]
        )
    assert result["rendered"] is True
    title.set_source_text.assert_called_once_with("DCC-MCP")
    subtitle.set_source_text.assert_called_once()
    title.set_keyframes.assert_called_once()
    project.import_file.assert_called_once_with(str(music))
    project.save.assert_called_once_with(str(project_path))
    render_queue.render.assert_called_once()
