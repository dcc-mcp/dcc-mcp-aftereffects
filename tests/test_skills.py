import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

SCRIPTS = (
    Path(__file__).parents[1]
    / "src"
    / "dcc_mcp_aftereffects"
    / "skills"
    / "aftereffects-project"
    / "scripts"
)


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
        (
            "list_compositions",
            (),
            {
                "compositions": [{"name": "Intro", "width": 1920, "height": 1080, "duration": 5.0}],
                "composition_count": 1,
            },
        ),
        (
            "save_project",
            (str(tmp_path / "intro.aep"),),
            {"path": str(tmp_path / "intro.aep"), "saved": True},
        ),
    )
    for name, args, expected in cases:
        module = load_script(name)
        with mock.patch.object(module, "AfterEffects", return_value=app):
            assert getattr(module, name)(*args) == expected
    project.save.assert_called_once_with(str(tmp_path / "intro.aep"))


def test_motion_intro_uses_typed_template_workflow(tmp_path):
    template = tmp_path / "template.aep"
    footage = tmp_path / "background.mp4"
    music = tmp_path / "music.mp3"
    template.write_bytes(b"aep")
    footage.write_bytes(b"mp4")
    music.write_bytes(b"mp3")
    title = SimpleNamespace(
        source_text=object(), set_source_text=mock.Mock(), set_keyframes=mock.Mock()
    )
    subtitle = SimpleNamespace(source_text=object(), set_source_text=mock.Mock())
    output_module = SimpleNamespace(set_output_path=mock.Mock())
    render_item = SimpleNamespace(output_module=mock.Mock(return_value=output_module))
    background_layer = SimpleNamespace(move_to_end=mock.Mock())
    composition = SimpleNamespace(
        name="Intro",
        layers=[title, subtitle],
        add_footage_layer=mock.Mock(side_effect=[background_layer, SimpleNamespace()]),
        add_to_render_queue=mock.Mock(return_value=render_item),
    )
    project_path = tmp_path / "result.aep"
    output_path = tmp_path / "result.mov"
    render_queue = SimpleNamespace(
        render=mock.Mock(side_effect=lambda: output_path.write_bytes(b"mov"))
    )
    project = SimpleNamespace(
        compositions=[composition],
        import_file=mock.Mock(return_value=SimpleNamespace()),
        save=mock.Mock(),
        render_queue=render_queue,
    )
    app = SimpleNamespace(open_project=mock.Mock(return_value=project))
    module = load_script("create_motion_intro")
    with mock.patch.object(module, "AfterEffects", return_value=app):
        result = module.create_motion_intro(
            str(template),
            str(project_path),
            str(output_path),
            footage_paths=[str(footage)],
            audio_paths=[str(music)],
        )
    assert result["rendered"] is True
    title.set_source_text.assert_called_once_with("DCC-MCP")
    subtitle.set_source_text.assert_called_once()
    title.set_keyframes.assert_called_once()
    assert result["footage_count"] == 1
    assert result["audio_count"] == 1
    assert result["output_size_bytes"] == 3
    assert project.import_file.call_args_list == [mock.call(str(footage)), mock.call(str(music))]
    background_layer.move_to_end.assert_called_once_with()
    project.save.assert_called_once_with(str(project_path))
    render_queue.render.assert_called_once()

    output_path.unlink()
    render_queue.render.side_effect = None
    with mock.patch.object(module, "AfterEffects", return_value=app):
        with pytest.raises(module.HostScriptError, match="render produced no output"):
            module.create_motion_intro(str(template), str(project_path), str(output_path))
