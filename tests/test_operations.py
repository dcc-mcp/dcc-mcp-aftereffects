from types import SimpleNamespace
from unittest import mock

import pytest
from adobe.core.dom import DomObject
from adobe.core.errors import HostScriptError

from dcc_mcp_aftereffects.operations import (
    TOOL_NAMESPACE_COVERAGE,
    configure_output_module,
    configure_render_queue_item,
    control_render_queue,
    create_composition,
    create_layer,
    evaluate_extend_script,
    inspect_composition,
    inspect_layer,
    inspect_render_queue,
    list_project_items,
    official_dom,
    queue_composition,
    update_layer,
)
from dcc_mcp_aftereffects.runtime import REQUIRED_METHODS


def item(**overrides):
    values = {
        "id": 1,
        "index": 1,
        "name": "Main",
        "item_type": "composition",
        "type_name": "CompItem",
        "parent_folder_id": None,
        "parent_folder_name": None,
        "selected": False,
        "width": 1920,
        "height": 1080,
        "duration": 5.0,
        "frame_rate": 24.0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def layer(**overrides):
    values = {
        "id": 10,
        "index": 1,
        "name": "Title",
        "layer_type": "text",
        "type_name": "TextLayer",
        "comp_id": 1,
        "source_id": None,
        "source_name": None,
        "selected": True,
        "enabled": True,
        "solo": False,
        "locked": False,
        "shy": False,
        "is_text": True,
        "start_time": 0.0,
        "in_point": 0.0,
        "out_point": 5.0,
        "stretch": 100.0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def render_item(**overrides):
    values = {
        "id": 20,
        "index": 1,
        "comp_id": 1,
        "comp_name": "Main",
        "status": "QUEUED",
        "elapsed_seconds": 0.0,
        "render": True,
        "skip_frames": 0,
        "queue_item_notify": False,
        "time_span_start": 0.0,
        "time_span_duration": 5.0,
        "num_output_modules": 1,
        "templates": ["Best Settings"],
        "settings": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def output_module(**overrides):
    values = {
        "item_index": 1,
        "index": 1,
        "name": "Lossless",
        "output_path": "output.mov",
        "include_source_xmp": False,
        "post_render_action": "NONE",
        "templates": ["Lossless"],
        "settings": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_tools_cover_every_advertised_bridge_namespace():
    assert set(TOOL_NAMESPACE_COVERAGE) == set(REQUIRED_METHODS)
    assert all(tools for tools in TOOL_NAMESPACE_COVERAGE.values())


def test_project_listing_and_composition_creation_use_typed_facade():
    composition = item(
        num_layers=0,
        work_area_start=0.0,
        work_area_duration=5.0,
        layers=[],
        selected_layers=[],
    )
    project = SimpleNamespace(
        items=[composition],
        compositions=[composition],
        footage_items=[],
        folders=[],
        selected_items=[],
        get_item_by_id=mock.Mock(return_value=composition),
        get_items_by_name=mock.Mock(return_value=[composition]),
        create_composition=mock.Mock(return_value=composition),
    )
    app_factory = mock.Mock(return_value=SimpleNamespace(project=project))

    assert list_project_items(item_id=1, app_factory=app_factory)["count"] == 1
    result = create_composition(
        "Main", 1920, 1080, 5.0, 24.0, pixel_aspect=1.0, app_factory=app_factory
    )

    assert result["created"] is True
    project.create_composition.assert_called_once_with(
        "Main",
        width=1920,
        height=1080,
        duration=5.0,
        frame_rate=24.0,
        pixel_aspect=1.0,
    )


def test_layer_tools_cover_details_creation_transform_keyframes_and_order():
    source_text = SimpleNamespace(
        text="Hello",
        font="Arial",
        font_size=48,
        fill_color=[1, 1, 1],
        stroke_color=[0, 0, 0],
        tracking=0,
        justification="CENTER_JUSTIFY",
    )
    effect = SimpleNamespace(
        id=1, index=1, name="Glow", match_name="ADBE Glo2", enabled=True, active=True
    )
    mask = SimpleNamespace(
        id=2,
        index=1,
        name="Mask 1",
        mask_mode="ADD",
        inverted=False,
        locked=False,
        opacity=100,
        feather=[0, 0],
        expansion=0,
    )
    updated = layer(name="Updated")
    text_layer = layer(source_text=source_text, effects=[effect], masks=[mask])
    text_layer.set_source_text = mock.Mock()
    text_layer.set_transform = mock.Mock(return_value=updated)
    updated.set_keyframes = mock.Mock(return_value=updated)
    updated.move_to_end = mock.Mock(return_value=updated)
    solid = layer(id=11, name="Solid", layer_type="solid", is_text=False)
    composition = item(
        num_layers=1,
        work_area_start=0.0,
        work_area_duration=5.0,
        layers=[text_layer],
        selected_layers=[text_layer],
        get_layer_by_id=mock.Mock(return_value=text_layer),
        add_solid_layer=mock.Mock(return_value=solid),
    )
    project = SimpleNamespace(compositions=[composition])
    app_factory = mock.Mock(return_value=SimpleNamespace(project=project))

    assert inspect_composition(1, app_factory=app_factory)["layers"][0]["name"] == "Title"
    explicit = inspect_composition(1, app_factory=app_factory)
    assert explicit["resolved_via"] == "explicit"
    details = inspect_layer(1, 10, app_factory=app_factory)
    assert details["source_text"]["text"] == "Hello"
    assert details["effects"][0]["name"] == "Glow"
    assert details["masks"][0]["name"] == "Mask 1"
    assert details["resolved_via"] == {"composition": "explicit", "layer": "explicit"}

    created = create_layer(1, "solid", color=[1, 0, 0], app_factory=app_factory)
    assert created["layer"]["name"] == "Solid"
    assert created["resolved_via"] == "explicit"
    composition.add_solid_layer.assert_called_once()

    result = update_layer(
        1,
        10,
        text="Updated",
        position=[100, 200],
        property_name="opacity",
        keyframes=[{"time": 0, "value": 0}, {"time": 1, "value": 100}],
        move="end",
        app_factory=app_factory,
    )
    assert result["layer"]["name"] == "Updated"
    assert result["resolved_via"] == {"composition": "explicit", "layer": "explicit"}
    text_layer.set_source_text.assert_called_once_with("Updated")
    text_layer.set_transform.assert_called_once_with(
        position=[100, 200], scale=None, rotation=None, opacity=None, anchor_point=None
    )
    updated.set_keyframes.assert_called_once()
    updated.move_to_end.assert_called_once_with()


def test_render_queue_tools_cover_queue_control_items_and_output_modules(tmp_path):
    module = output_module()
    module.set_output_path = mock.Mock(return_value=module)
    queued = render_item()
    queued.set_render = mock.Mock(return_value=queued)
    queued.output_module = mock.Mock(return_value=module)
    composition = item(
        num_layers=0,
        work_area_start=0.0,
        work_area_duration=5.0,
        add_to_render_queue=mock.Mock(return_value=queued),
    )
    queue = SimpleNamespace(
        item_count=1,
        can_queue_in_ame=True,
        queue_notify=False,
        rendering=False,
        items=[queued],
        refresh=mock.Mock(),
        render_queue=mock.Mock(),
        get_item_by_index=mock.Mock(return_value=queued),
    )
    queue.refresh.return_value = queue
    queue.render_queue.return_value = queue
    project = SimpleNamespace(compositions=[composition])
    app_factory = mock.Mock(return_value=SimpleNamespace(project=project, render_queue=queue))

    assert inspect_render_queue(app_factory=app_factory)["item_count"] == 1
    output = tmp_path / "main.mov"
    assert queue_composition(1, output_path=str(output), app_factory=app_factory)["queued"] is True
    assert control_render_queue("render", app_factory=app_factory)["operation"] == "render"
    assert configure_render_queue_item(1, render=False, app_factory=app_factory)["updated"] is True
    configured = configure_output_module(1, output_path=str(output), app_factory=app_factory)
    assert configured["output_module"]["name"] == "Lossless"
    module.set_output_path.assert_called_once_with(str(output))


class FakeDom:
    def root(self, name):
        return DomObject(self, name, "Application")

    def get(self, receiver, member):
        assert receiver.reference == "app"
        return {"member": member, "child": DomObject(self, "project", "Project")}


def test_official_dom_round_trips_opaque_refs_and_raw_fallback():
    dom = FakeDom()
    raw = SimpleNamespace(eval_extend_script=mock.Mock(return_value={"ok": True}))
    app_factory = mock.Mock(return_value=SimpleNamespace(dom=dom, raw=raw))

    root = official_dom("root", app_factory=app_factory)
    assert root["result"] == {"$ref": "app", "$type": "Application"}
    result = official_dom(
        "get",
        receiver=root["result"],
        member="project",
        app_factory=app_factory,
    )
    assert result["result"]["child"] == {"$ref": "project", "$type": "Project"}

    assert evaluate_extend_script("1 + 1", app_factory=app_factory) == {"result": {"ok": True}}
    raw.eval_extend_script.assert_called_once_with("1 + 1", timeout_ms=None)


def _app_with(compositions, active_item=None):
    project = SimpleNamespace(
        items=list(compositions),
        compositions=list(compositions),
        footage_items=[],
        folders=[],
        selected_items=[],
    )
    return mock.Mock(
        return_value=SimpleNamespace(project=project, active_item=active_item, selected_items=[])
    )


def _resolvable_composition(**overrides):
    values = {
        "num_layers": 1,
        "work_area_start": 0.0,
        "work_area_duration": 5.0,
        "layers": [],
        "selected_layers": [],
        "get_layer_by_id": mock.Mock(return_value=None),
    }
    values.update(overrides)
    return item(**values)


def test_composition_resolution_falls_back_to_active_then_selected_then_first():
    active = _resolvable_composition(id=1, name="Active")
    second = _resolvable_composition(id=2, name="Second", selected=True)

    active_app = _app_with([second, active], active_item=active)
    result = inspect_composition(app_factory=active_app)
    assert result["composition"]["name"] == "Active"
    assert result["resolved_via"] == "active_item"

    selected_app = _app_with([second, active])
    result = inspect_composition(app_factory=selected_app)
    assert result["composition"]["name"] == "Second"
    assert result["resolved_via"] == "selected"

    first_app = _app_with([active, _resolvable_composition(id=2, name="Later")])
    result = inspect_composition(app_factory=first_app)
    assert result["composition"]["name"] == "Active"
    assert result["resolved_via"] == "first"


def test_composition_resolution_without_candidates_reports_a_host_error():
    app_factory = _app_with([])
    with pytest.raises(HostScriptError, match="no composition to resolve"):
        inspect_composition(app_factory=app_factory)


def test_layer_resolution_uses_the_single_selected_layer():
    selected = layer(
        id=10,
        name="Selected",
        selected=True,
        source_text=None,
        effects=[],
        masks=[],
    )
    other = layer(id=11, name="Other", selected=False)
    composition = _resolvable_composition(
        id=1, name="Main", layers=[other, selected], selected_layers=[selected]
    )
    app_factory = _app_with([composition], active_item=composition)

    result = inspect_layer(app_factory=app_factory)
    assert result["layer"]["name"] == "Selected"
    assert result["resolved_via"] == {"composition": "active_item", "layer": "selected"}


def test_layer_resolution_rejects_ambiguous_selection_and_empty_selection():
    first = layer(id=10, name="First", selected=True)
    second = layer(id=11, name="Second", selected=True)
    multiple = _resolvable_composition(
        id=1, name="Multiple", layers=[first, second], selected_layers=[first, second]
    )
    with pytest.raises(HostScriptError, match="2 selected layers"):
        inspect_layer(1, app_factory=_app_with([multiple], active_item=multiple))

    unselected = layer(id=12, name="Unselected", selected=False)
    none = _resolvable_composition(id=2, name="None", layers=[unselected], selected_layers=[])
    with pytest.raises(HostScriptError, match="no selected layer"):
        inspect_layer(2, app_factory=_app_with([none], active_item=none))


def test_mutation_and_render_tools_inherit_composition_resolution():
    solid = layer(id=11, name="Solid", layer_type="solid", is_text=False)
    composition = _resolvable_composition(
        id=1,
        name="Main",
        layers=[layer(id=10, name="Title", selected=True)],
        selected_layers=[layer(id=10, name="Title", selected=True)],
        add_solid_layer=mock.Mock(return_value=solid),
        add_to_render_queue=mock.Mock(return_value=render_item()),
    )
    app_factory = _app_with([composition], active_item=composition)

    created = create_layer(layer_type="solid", color=[1, 0, 0], app_factory=app_factory)
    assert created["resolved_via"] == "active_item"
    composition.add_solid_layer.assert_called_once()

    queued = queue_composition(app_factory=app_factory)
    assert queued["resolved_via"] == "active_item"
    composition.add_to_render_queue.assert_called_once()
