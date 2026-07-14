from pathlib import Path

from adobe.after_effects import AfterEffects
from adobe.core.errors import HostScriptError
from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry


def _absolute_path(value, suffix=None, must_exist=False):
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"Expected an absolute path: {value}")
    if suffix and path.suffix.lower() != suffix:
        raise ValueError(f"Expected a {suffix} path: {value}")
    if must_exist and not path.is_file():
        raise FileNotFoundError(path)
    return str(path)


def create_motion_intro(
    template_path,
    project_path,
    output_path,
    title="DCC-MCP",
    subtitle="One protocol. Every creative app.",
    footage_paths=None,
    audio_paths=None,
):
    template_path = _absolute_path(template_path, ".aep", must_exist=True)
    project_path = _absolute_path(project_path, ".aep")
    output_path = _absolute_path(output_path)
    footage_paths = [_absolute_path(path, must_exist=True) for path in footage_paths or []]
    audio_paths = [_absolute_path(path, must_exist=True) for path in audio_paths or []]

    app = AfterEffects()
    project = app.open_project(template_path)
    compositions = project.compositions
    if not compositions:
        raise HostScriptError("After Effects template has no compositions")
    composition = compositions[0]
    text_layers = [layer for layer in composition.layers if layer.source_text is not None]
    if text_layers:
        text_layers[0].set_source_text(title)
    else:
        text_layers.append(composition.add_text_layer(title, name="DCC-MCP Title"))
    if len(text_layers) > 1:
        text_layers[1].set_source_text(subtitle)
    else:
        text_layers.append(composition.add_text_layer(subtitle, name="DCC-MCP Subtitle"))
    text_layers[0].set_keyframes(
        "scale",
        [{"time": 0, "value": [0, 0]}, {"time": 0.8, "value": [100, 100]}],
    )

    for path in footage_paths:
        footage_layer = composition.add_footage_layer(project.import_file(path))
        footage_layer.move_to_end()

    for path in audio_paths:
        composition.add_footage_layer(project.import_file(path))

    project.save(project_path)
    render_item = composition.add_to_render_queue(output_path=output_path)
    render_item.output_module(1).set_output_path(output_path)
    project.render_queue.render()
    rendered_output = Path(output_path)
    if not rendered_output.is_file() or rendered_output.stat().st_size == 0:
        raise HostScriptError(f"After Effects render produced no output: {output_path}")
    return {
        "template_path": template_path,
        "project_path": project_path,
        "output_path": output_path,
        "composition": composition.name,
        "footage_count": len(footage_paths),
        "audio_count": len(audio_paths),
        "output_size_bytes": rendered_output.stat().st_size,
        "rendered": True,
    }


@skill_entry
def main(**kwargs):
    return action_result("After Effects motion intro rendered.", create_motion_intro, **kwargs)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
