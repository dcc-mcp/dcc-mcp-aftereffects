from types import SimpleNamespace

from dcc_mcp_aftereffects.context import collect_context


def test_context_is_bounded_and_omits_project_path():
    client = object()
    project = SimpleNamespace(name="Demo", item_count=3, path="private/project.aep")
    app = SimpleNamespace(
        project=project,
        active_item=SimpleNamespace(name="Main"),
        version="24.6",
    )
    snapshot = collect_context(
        broker_url="http://127.0.0.1:47391",
        token="secret",
        target="default",
        timeout=1.0,
        client_factory=lambda **_kwargs: client,
        app_factory=lambda **_kwargs: app,
    ).to_dict()

    assert snapshot == {
        "dcc": "aftereffects",
        "document": {"name": "Demo"},
        "active_object": {"name": "Main"},
        "counts": {"items": 3},
        "metadata": {"version": "24.6", "target": "default"},
    }
