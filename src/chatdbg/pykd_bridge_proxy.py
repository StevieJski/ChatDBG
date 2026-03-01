"""
pykd proxy module — provides a fake ``pykd`` interface that forwards
all calls over TCP to the bridge server running in Python 3.9 / CDB.

This module is injected into ``sys.modules["pykd"]`` by
``pykd_bridge_client.py`` before ``chatdbg_windbg.py`` is imported,
so all ``import pykd`` statements transparently resolve to this proxy.

Environment variable ``CHATDBG_PYKD_PORT`` must be set to the TCP port
of the bridge server.
"""

import atexit
import json
import os
import socket
import types


# ---------------------------------------------------------------------------
# Internal TCP connection
# ---------------------------------------------------------------------------

_conn = None


def _get_conn():
    global _conn
    if _conn is None:
        port = int(os.environ["CHATDBG_PYKD_PORT"])
        _conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _conn.connect(("127.0.0.1", port))
        _conn.settimeout(600)
    return _conn


def _call(request):
    """Send a JSON request and return the parsed response."""
    conn = _get_conn()
    payload = json.dumps(request) + "\n"
    conn.sendall(payload.encode("utf-8"))

    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            raise ConnectionError("Bridge server closed connection")
        buf += chunk

    line, _ = buf.split(b"\n", 1)
    resp = json.loads(line.decode("utf-8"))
    if not resp.get("ok"):
        raise Exception(resp.get("error", "Unknown bridge error"))
    return resp.get("result")


def _shutdown():
    global _conn
    if _conn is not None:
        try:
            _call({"type": "quit"})
        except Exception:
            pass
        try:
            _conn.close()
        except Exception:
            pass
        _conn = None


atexit.register(_shutdown)


# ---------------------------------------------------------------------------
# Public pykd-compatible API
# ---------------------------------------------------------------------------


def dbgCommand(command):
    """Run a debugger command and return its text output."""
    return _call({"type": "dbgCommand", "command": command})


class _StackFrame:
    """Lightweight stand-in for pykd.stackFrame."""

    def __init__(self, data):
        self.instructionOffset = data["instructionOffset"]
        self.returnOffset = data["returnOffset"]
        self.frameOffset = data["frameOffset"]
        self.stackOffset = data["stackOffset"]


def getStack():
    """Return a list of stack frame objects."""
    frames_data = _call({"type": "getStack"})
    return [_StackFrame(f) for f in frames_data]


def findSymbol(offset):
    """Resolve an address to a symbol name."""
    return _call({"type": "findSymbol", "offset": offset})


def getExecutionStatus():
    """Return the debugger execution status (1 = Break)."""
    return _call({"type": "getExecutionStatus"})
