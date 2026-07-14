"""Minimal localhost request broker shared by the MCP server and CEP panel."""

from __future__ import annotations

import json
import os
import queue
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.request import Request, urlopen


class BridgeBroker:
    """Queue typed requests until the installed Adobe panel completes them."""

    def __init__(self, prefix: str, default_port: int) -> None:
        self._prefix = prefix
        self._port = int(os.environ.get(f"{prefix}_BRIDGE_PORT", default_port))
        self._token = os.environ.get(f"{prefix}_BRIDGE_TOKEN", "dev-token")
        self._pending: queue.Queue[dict[str, Any]] = queue.Queue()
        self._waiting: dict[str, tuple[threading.Event, dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        os.environ.setdefault(f"{prefix}_BRIDGE_URL", f"http://127.0.0.1:{self._port}")

    def start(self) -> None:
        if self._httpd is not None:
            return
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/next" or not self._authorized():
                    return self._send(403, {"error": "forbidden"})
                self._send(200, broker.next())

            def do_POST(self):  # noqa: N802
                if not self._authorized():
                    return self._send(403, {"error": "forbidden"})
                try:
                    payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                except (KeyError, ValueError, json.JSONDecodeError):
                    return self._send(400, {"error": "invalid JSON"})
                if self.path == "/call":
                    try:
                        return self._send(
                            200, broker.submit(payload["action"], payload.get("params", {}))
                        )
                    except (KeyError, RuntimeError) as error:
                        return self._send(503, {"error": str(error)})
                if self.path == "/result":
                    broker.resolve(
                        payload.get("id", ""), payload.get("result"), payload.get("error")
                    )
                    return self._send(200, {"ok": True})
                return self._send(404, {"error": "not found"})

            def log_message(self, *_: Any) -> None:
                return

            def _authorized(self) -> bool:
                return self.headers.get("X-DCC-MCP-Token") == broker._token

            def _send(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self._port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def submit(self, action: str, params: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        completed, result = threading.Event(), {}
        with self._lock:
            self._waiting[request_id] = (completed, result)
        self._pending.put({"id": request_id, "action": action, "params": params})
        if not completed.wait(timeout):
            with self._lock:
                self._waiting.pop(request_id, None)
            raise RuntimeError("Adobe bridge did not respond; open the bundled CEP panel")
        if "error" in result:
            raise RuntimeError(str(result["error"]))
        return result.get("result", {})

    def next(self) -> dict[str, Any]:
        try:
            return self._pending.get(timeout=25)
        except queue.Empty:
            return {"id": None}

    def resolve(self, request_id: str, result: Any, error: Any) -> None:
        with self._lock:
            waiting = self._waiting.pop(request_id, None)
        if waiting is None:
            return
        completed, payload = waiting
        if error:
            payload["error"] = error
        else:
            payload["result"] = result if isinstance(result, dict) else {"value": result}
        completed.set()


def call_bridge(prefix: str, action: str, params: dict[str, Any]) -> dict[str, Any]:
    """Call a running adapter-local bridge from a skill subprocess."""
    url = os.environ[f"{prefix}_BRIDGE_URL"].rstrip("/") + "/call"
    token = os.environ.get(f"{prefix}_BRIDGE_TOKEN", "dev-token")
    request = Request(
        url,
        data=json.dumps({"action": action, "params": params}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-DCC-MCP-Token": token},
        method="POST",
    )
    with urlopen(request, timeout=35) as response:  # noqa: S310 - loopback URL is adapter-owned.
        payload = json.loads(response.read().decode("utf-8"))
    if "error" in payload:
        raise RuntimeError(payload["error"])
    return payload
