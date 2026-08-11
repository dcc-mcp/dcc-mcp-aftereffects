"""Typed After Effects operations shared by bundled MCP skills."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from adobe.after_effects import AfterEffects
from adobe.core.dom import DomObject
from adobe.core.errors import HostScriptError

TOOL_NAMESPACE_COVERAGE = {
    "app": ("open_project",),
    "project": ("list_project_items", "import_file", "create_composition", "save_project"),
    "item": ("list_project_items",),
    "layer": ("inspect_composition", "inspect_layer", "create_layer", "update_layer"),
    "mask": ("inspect_layer",),
    "effect": ("inspect_layer",),
    "text": ("inspect_layer", "update_layer"),
    "renderQueue": ("inspect_render_queue", "queue_composition", "control_render_queue"),
    "renderQueueItem": ("configure_render_queue_item",),
    "outputModule": ("configure_output_module",),
    "dom": ("official_dom",),
    "raw": ("evaluate_extend_script",),
}


def _absolute_path(value: str, *, must_exist: bool = False, suffix: str | None = None) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"Expected an absolute path: {value}")
    if suffix and path.suffix.lower() != suffix:
        raise ValueError(f"Expected a {suffix} path: {value}")
    if must_exist and not path.is_file():
        raise FileNotFoundError(path)
    return str(path)


def _project(app: Any) -> Any:
    project = app.project
    if project is None:
        raise HostScriptError("After Effects has no active project")
    return project


def _item_data(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "index": item.index,
        "name": item.name,
        "type": item.item_type or item.type_name,
        "parent_folder_id": item.parent_folder_id,
        "parent_folder_name": item.parent_folder_name,
        "selected": item.selected,
        "width": getattr(item, "width", None),
        "height": getattr(item, "height", None),
        "duration": getattr(item, "duration", None),
        "frame_rate": getattr(item, "frame_rate", None),
    }


def _composition_data(composition: Any) -> dict[str, Any]:
    return {
        **_item_data(composition),
        "num_layers": composition.num_layers,
        "work_area_start": composition.work_area_start,
        "work_area_duration": composition.work_area_duration,
    }


def _layer_data(layer: Any) -> dict[str, Any]:
    return {
        "id": layer.id,
        "index": layer.index,
        "name": layer.name,
        "type": layer.layer_type or layer.type_name,
        "composition_id": layer.comp_id,
        "source_id": layer.source_id,
        "source_name": layer.source_name,
        "selected": layer.selected,
        "enabled": layer.enabled,
        "solo": layer.solo,
        "locked": layer.locked,
        "shy": layer.shy,
        "is_text": layer.is_text,
        "start_time": layer.start_time,
        "in_point": layer.in_point,
        "out_point": layer.out_point,
        "stretch": layer.stretch,
    }


def _find_by_key(values: Iterable[Any], key: Any, label: str) -> Any:
    for value in values:
        if key in {value.id, value.index, value.name} or str(key) in {
            str(value.id),
            str(value.index),
            str(value.name),
        }:
            return value
    raise HostScriptError(f"After Effects {label} was not found: {key}")


def _composition(project: Any, key: Any) -> Any:
    return _find_by_key(project.compositions, key, "composition")


def _layer(composition: Any, key: Any) -> Any:
    layer = composition.get_layer_by_id(key)
    return layer if layer is not None else _find_by_key(composition.layers, key, "layer")


def inspect_project(*, app_factory=AfterEffects) -> dict[str, Any]:
    app = app_factory()
    project = _project(app)
    active = app.active_item
    return {
        "version": app.version,
        "project_name": project.name,
        "item_count": project.item_count,
        "active_item": _item_data(active) if active else None,
        "selected_items": [_item_data(item) for item in app.selected_items],
    }


def open_project(path: str, *, app_factory=AfterEffects) -> dict[str, Any]:
    project = app_factory().open_project(_absolute_path(path, must_exist=True, suffix=".aep"))
    return {"name": project.name, "item_count": project.item_count, "opened": True}


def save_project(path: str | None = None, *, app_factory=AfterEffects) -> dict[str, Any]:
    project = _project(app_factory())
    saved = project.save(_absolute_path(path, suffix=".aep") if path else None)
    return {"name": saved.name, "saved": True}


def list_project_items(
    kind: str = "all",
    *,
    item_id: Any = None,
    name: str | None = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    project = _project(app_factory())
    if item_id is not None:
        item = project.get_item_by_id(item_id)
        values = [item] if item is not None else []
    elif name is not None:
        values = project.get_items_by_name(name)
    else:
        collections = {
            "all": project.items,
            "composition": project.compositions,
            "footage": project.footage_items,
            "folder": project.folders,
            "selected": project.selected_items,
        }
        if kind not in collections:
            raise ValueError(f"Unsupported item kind: {kind}")
        values = collections[kind]
    return {"items": [_item_data(item) for item in values], "count": len(values)}


def import_file(
    path: str,
    *,
    sequence: bool = False,
    force_alphabetical: bool = False,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    project = _project(app_factory())
    item = project.import_file(
        _absolute_path(path, must_exist=True),
        sequence=sequence,
        force_alphabetical=force_alphabetical,
    )
    return {"item": _item_data(item), "imported": True}


def create_composition(
    name: str,
    width: int,
    height: int,
    duration: float,
    frame_rate: float,
    *,
    pixel_aspect: float = 1.0,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    composition = _project(app_factory()).create_composition(
        name,
        width=width,
        height=height,
        duration=duration,
        frame_rate=frame_rate,
        pixel_aspect=pixel_aspect,
    )
    return {"composition": _composition_data(composition), "created": True}


def inspect_composition(composition: Any, *, app_factory=AfterEffects) -> dict[str, Any]:
    value = _composition(_project(app_factory()), composition)
    return {
        "composition": _composition_data(value),
        "layers": [_layer_data(layer) for layer in value.layers],
        "selected_layers": [_layer_data(layer) for layer in value.selected_layers],
    }


def inspect_layer(composition: Any, layer: Any, *, app_factory=AfterEffects) -> dict[str, Any]:
    comp = _composition(_project(app_factory()), composition)
    value = _layer(comp, layer)
    source_text = value.source_text
    return {
        "layer": _layer_data(value),
        "source_text": {
            "text": source_text.text,
            "font": source_text.font,
            "font_size": source_text.font_size,
            "fill_color": source_text.fill_color,
            "stroke_color": source_text.stroke_color,
            "tracking": source_text.tracking,
            "justification": source_text.justification,
        }
        if source_text
        else None,
        "effects": [
            {
                "id": effect.id,
                "index": effect.index,
                "name": effect.name,
                "match_name": effect.match_name,
                "enabled": effect.enabled,
                "active": effect.active,
            }
            for effect in value.effects
        ],
        "masks": [
            {
                "id": mask.id,
                "index": mask.index,
                "name": mask.name,
                "mode": mask.mask_mode,
                "inverted": mask.inverted,
                "locked": mask.locked,
                "opacity": mask.opacity,
                "feather": mask.feather,
                "expansion": mask.expansion,
            }
            for mask in value.masks
        ],
    }


def create_layer(
    composition: Any,
    layer_type: str,
    *,
    text: str | None = None,
    name: str | None = None,
    color: list[float] | None = None,
    width: int | None = None,
    height: int | None = None,
    pixel_aspect: float = 1.0,
    duration: float | None = None,
    footage_item: Any = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    project = _project(app_factory())
    comp = _composition(project, composition)
    if layer_type == "text":
        if text is None:
            raise ValueError("text is required for a text layer")
        value = comp.add_text_layer(text, name=name)
    elif layer_type == "solid":
        if color is None:
            raise ValueError("color is required for a solid layer")
        value = comp.add_solid_layer(
            color,
            name=name or "Solid",
            width=width,
            height=height,
            pixel_aspect=pixel_aspect,
            duration=duration,
        )
    elif layer_type == "footage":
        if footage_item is None:
            raise ValueError("footage_item is required for a footage layer")
        item = project.get_item_by_id(footage_item)
        if item is None:
            item = _find_by_key(project.footage_items, footage_item, "footage item")
        value = comp.add_footage_layer(item, duration=duration)
    else:
        raise ValueError(f"Unsupported layer type: {layer_type}")
    return {"layer": _layer_data(value), "created": True}


def update_layer(
    composition: Any,
    layer: Any,
    *,
    text: str | None = None,
    text_properties: dict[str, Any] | None = None,
    position: list[float] | None = None,
    scale: list[float] | None = None,
    rotation: float | None = None,
    opacity: float | None = None,
    anchor_point: list[float] | None = None,
    property_name: str | None = None,
    keyframes: list[dict[str, Any]] | None = None,
    move: str | None = None,
    relative_to: Any = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    comp = _composition(_project(app_factory()), composition)
    value = _layer(comp, layer)
    if text is not None:
        value.set_source_text(text, **(text_properties or {}))
    if any(item is not None for item in (position, scale, rotation, opacity, anchor_point)):
        value = value.set_transform(
            position=position,
            scale=scale,
            rotation=rotation,
            opacity=opacity,
            anchor_point=anchor_point,
        )
    if property_name is not None or keyframes is not None:
        if property_name is None or keyframes is None:
            raise ValueError("property_name and keyframes must be provided together")
        value = value.set_keyframes(property_name, keyframes)
    if move == "beginning":
        value = value.move_to_beginning()
    elif move == "end":
        value = value.move_to_end()
    elif move in {"before", "after"}:
        if relative_to is None:
            raise ValueError("relative_to is required for before/after moves")
        target = _layer(comp, relative_to)
        value = value.move_before(target) if move == "before" else value.move_after(target)
    elif move is not None:
        raise ValueError(f"Unsupported layer move: {move}")
    return {"layer": _layer_data(value), "updated": True}


def _render_item_data(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "index": item.index,
        "composition_id": item.comp_id,
        "composition_name": item.comp_name,
        "status": item.status,
        "elapsed_seconds": item.elapsed_seconds,
        "render": item.render,
        "skip_frames": item.skip_frames,
        "notify": item.queue_item_notify,
        "time_span_start": item.time_span_start,
        "time_span_duration": item.time_span_duration,
        "num_output_modules": item.num_output_modules,
        "templates": item.templates,
        "settings": item.settings,
    }


def _output_module_data(module: Any) -> dict[str, Any]:
    return {
        "item_index": module.item_index,
        "index": module.index,
        "name": module.name,
        "output_path": module.output_path,
        "include_source_xmp": module.include_source_xmp,
        "post_render_action": module.post_render_action,
        "templates": module.templates,
        "settings": module.settings,
    }


def inspect_render_queue(*, app_factory=AfterEffects) -> dict[str, Any]:
    queue = app_factory().render_queue.refresh()
    return {
        "item_count": queue.item_count,
        "can_queue_in_ame": queue.can_queue_in_ame,
        "queue_notify": queue.queue_notify,
        "rendering": queue.rendering,
        "items": [_render_item_data(item) for item in queue.items],
    }


def queue_composition(
    composition: Any,
    *,
    render_settings_template: str | None = None,
    output_module_template: str | None = None,
    output_path: str | None = None,
    settings: dict[str, Any] | None = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    comp = _composition(_project(app_factory()), composition)
    item = comp.add_to_render_queue(
        render_settings_template=render_settings_template,
        output_module_template=output_module_template,
        output_path=_absolute_path(output_path) if output_path else None,
        **(settings or {}),
    )
    return {"item": _render_item_data(item), "queued": True}


def control_render_queue(
    operation: str,
    *,
    enabled: bool = True,
    queue_in_ame_start: bool = False,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    queue = app_factory().render_queue
    if operation == "render":
        queue = queue.render_queue()
    elif operation == "pause":
        queue = queue.pause_rendering(enabled)
    elif operation == "stop":
        queue = queue.stop_rendering()
    elif operation == "show":
        queue = queue.show_window(enabled)
    elif operation == "queue_in_ame":
        queue = queue.queue_in_ame(queue_in_ame_start)
    elif operation == "notify":
        queue = queue.set_queue_notify(enabled)
    else:
        raise ValueError(f"Unsupported render queue operation: {operation}")
    return {"operation": operation, "item_count": queue.item_count, "rendering": queue.rendering}


def configure_render_queue_item(
    index: int,
    *,
    template: str | None = None,
    settings: dict[str, Any] | None = None,
    render: bool | None = None,
    notify: bool | None = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    item = app_factory().render_queue.get_item_by_index(index)
    if item is None:
        raise HostScriptError(f"After Effects render queue item was not found: {index}")
    if template is not None:
        item = item.apply_template(template)
    if settings is not None:
        item = item.set_settings(settings)
    if render is not None:
        item = item.set_render(render)
    if notify is not None:
        item = item.set_queue_item_notify(notify)
    return {"item": _render_item_data(item), "updated": True}


def configure_output_module(
    item_index: int,
    module_index: int = 1,
    *,
    template: str | None = None,
    settings: dict[str, Any] | None = None,
    output_path: str | None = None,
    save_template: str | None = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    item = app_factory().render_queue.get_item_by_index(item_index)
    if item is None:
        raise HostScriptError(f"After Effects render queue item was not found: {item_index}")
    module = item.output_module(module_index)
    if module is None:
        raise HostScriptError(
            f"After Effects output module was not found: item {item_index}, module {module_index}"
        )
    if template is not None:
        module = module.apply_template(template)
    if settings is not None:
        module = module.set_settings(settings)
    if output_path is not None:
        module = module.set_output_path(_absolute_path(output_path))
    if save_template is not None:
        module = module.save_as_template(save_template)
    return {"output_module": _output_module_data(module), "updated": True}


def _decode_dom_input(value: Any, namespace: Any) -> Any:
    if isinstance(value, list):
        return [_decode_dom_input(item, namespace) for item in value]
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            return DomObject(namespace, reference, value.get("$type"))
        return {key: _decode_dom_input(item, namespace) for key, item in value.items()}
    return value


def _encode_dom_output(value: Any) -> Any:
    if isinstance(value, DomObject):
        result = {"$ref": value.reference}
        if value.type_name:
            result["$type"] = value.type_name
        return result
    if isinstance(value, list):
        return [_encode_dom_output(item) for item in value]
    if isinstance(value, dict):
        return {key: _encode_dom_output(item) for key, item in value.items()}
    return value


def official_dom(
    operation: str,
    *,
    receiver: dict[str, Any] | None = None,
    member: str | int | None = None,
    value: Any = None,
    args: list[Any] | None = None,
    members: list[str | int] | None = None,
    root: str = "app",
    command_name: str | None = None,
    mutating: bool = False,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    namespace = app_factory().dom
    if operation == "root":
        result = namespace.root(root)
    else:
        if receiver is None:
            raise ValueError("receiver is required for this DOM operation")
        target = _decode_dom_input(receiver, namespace)
        if not isinstance(target, DomObject):
            raise ValueError("receiver must contain a $ref")
        decoded_args = _decode_dom_input(args or [], namespace)
        if operation == "get":
            result = namespace.get(target, member)
        elif operation == "set":
            result = namespace.set(
                target, member, _decode_dom_input(value, namespace), command_name=command_name
            )
        elif operation == "call":
            result = namespace.call(
                target,
                member,
                *decoded_args,
                command_name=command_name,
                mutating=mutating,
            )
        elif operation == "construct":
            result = namespace.construct(
                target, str(member), *decoded_args, command_name=command_name
            )
        elif operation == "keys":
            result = namespace.keys(target)
        elif operation == "snapshot":
            result = namespace.snapshot(target, *(members or []))
        elif operation == "release":
            result = namespace.release(target)
        else:
            raise ValueError(f"Unsupported DOM operation: {operation}")
    return {"operation": operation, "result": _encode_dom_output(result)}


def evaluate_extend_script(
    source: str,
    *,
    args: list[Any] | None = None,
    timeout_ms: int | None = None,
    app_factory=AfterEffects,
) -> dict[str, Any]:
    result = app_factory().raw.eval_extend_script(source, *(args or []), timeout_ms=timeout_ms)
    return {"result": result}


__all__ = [
    "TOOL_NAMESPACE_COVERAGE",
    "configure_output_module",
    "configure_render_queue_item",
    "control_render_queue",
    "create_composition",
    "create_layer",
    "evaluate_extend_script",
    "import_file",
    "inspect_composition",
    "inspect_layer",
    "inspect_project",
    "inspect_render_queue",
    "list_project_items",
    "official_dom",
    "open_project",
    "queue_composition",
    "save_project",
    "update_layer",
]
