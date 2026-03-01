"""
pykd bridge server — runs in Python 3.9 under CDB via pykd bootstrapper.

Starts a TCP server on localhost that proxies pykd API calls from a
Python 3.11+ ChatDBG subprocess.  This bridges the version gap:
the pykd bootstrapper only supports Python ≤ 3.9, but ChatDBG requires ≥ 3.11.

Usage in CDB::

    .load pykd
    !py -3.9 -g <path>/pykd_bridge_server.py [user-args...]

Protocol: newline-delimited JSON over TCP.

Request format::

    {"type": "dbgCommand", "command": "k 20"}
    {"type": "getExecutionStatus"}
    {"type": "getStack"}
    {"type": "findSymbol", "offset": 12345}
    {"type": "quit"}

Response format::

    {"ok": true, "result": "..."}
    {"ok": false, "error": "..."}
"""

import json
import os
import socket
import subprocess
import sys

import pykd


def _find_python():
    """Find Python 3.11+ for the ChatDBG subprocess."""
    for ver in ["3.12", "3.11"]:
        try:
            result = subprocess.run(
                ["py", "-" + ver, "-c", "import sys; print(sys.executable)"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
    return None


def _handle_request(data):
    """Execute a pykd call and return a JSON response."""
    try:
        req = json.loads(data)
    except json.JSONDecodeError as exc:
        return json.dumps({"ok": False, "error": "Bad JSON: " + str(exc)})

    kind = req.get("type", "")

    if kind == "dbgCommand":
        try:
            result = pykd.dbgCommand(req["command"])
            return json.dumps({"ok": True, "result": result or ""})
        except Exception as exc:
            return json.dumps({"ok": False, "error": str(exc)})

    elif kind == "getExecutionStatus":
        try:
            return json.dumps({"ok": True, "result": pykd.getExecutionStatus()})
        except Exception as exc:
            return json.dumps({"ok": False, "error": str(exc)})

    elif kind == "getStack":
        try:
            frames = []
            for f in pykd.getStack():
                frames.append(
                    {
                        "instructionOffset": f.instructionOffset,
                        "returnOffset": f.returnOffset,
                        "frameOffset": f.frameOffset,
                        "stackOffset": f.stackOffset,
                    }
                )
            return json.dumps({"ok": True, "result": frames})
        except Exception as exc:
            return json.dumps({"ok": False, "error": str(exc)})

    elif kind == "findSymbol":
        try:
            sym = pykd.findSymbol(req["offset"])
            return json.dumps({"ok": True, "result": sym})
        except Exception as exc:
            return json.dumps({"ok": False, "error": str(exc)})

    elif kind == "ping":
        return json.dumps({"ok": True, "result": "pong"})

    elif kind == "quit":
        return json.dumps({"ok": True, "result": "bye"})

    else:
        return json.dumps({"ok": False, "error": "Unknown type: " + kind})


def main():
    python_exe = _find_python()
    if not python_exe:
        print("[ChatDBG bridge] ERROR: Python 3.11+ not found.")
        return 1

    print("[ChatDBG bridge] Python 3.11+ at:", python_exe)

    # Bind to an ephemeral port on localhost
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(60)
    print("[ChatDBG bridge] Listening on port", port)

    # Prepare environment for the ChatDBG subprocess
    env = os.environ.copy()
    env["CHATDBG_PYKD_PORT"] = str(port)

    # Locate chatdbg_windbg.py relative to this script
    # Note: __file__ is not set when running under pykd; use sys.argv[0]
    this_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    windbg_script = os.path.join(this_dir, "chatdbg_windbg.py")

    # Forward command-line args (user's question, etc.)
    user_args = sys.argv[1:] if len(sys.argv) > 1 else []

    # The client script sets up the pykd proxy, then imports chatdbg_windbg
    client_script = os.path.join(this_dir, "pykd_bridge_client.py")

    cmd = [python_exe, client_script] + user_args
    print("[ChatDBG bridge] Launching:", " ".join(cmd))

    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL)

    try:
        conn, addr = srv.accept()
        print("[ChatDBG bridge] Client connected from", addr)
        conn.settimeout(600)  # 10 minute overall timeout

        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                resp = _handle_request(line.decode("utf-8"))
                conn.sendall((resp + "\n").encode("utf-8"))

                # On quit, clean up and return
                try:
                    if json.loads(line.decode("utf-8")).get("type") == "quit":
                        conn.close()
                        proc.wait(timeout=10)
                        return 0
                except Exception:
                    pass

    except socket.timeout:
        print("[ChatDBG bridge] Timeout waiting for client")
    except Exception as exc:
        print("[ChatDBG bridge] Error:", exc)
    finally:
        srv.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    return proc.returncode if proc.returncode is not None else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
