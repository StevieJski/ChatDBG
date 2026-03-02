"""
End-to-end test runner for DotnetCrashSample scenarios with ChatDBG.

Usage:
    py -3.12 run_e2e_test.py nullref
    py -3.12 run_e2e_test.py deadlock          # hang mode — sends break after delay
    py -3.12 run_e2e_test.py --all              # run all modes sequentially
    py -3.12 run_e2e_test.py --list             # list available modes

For crash modes (nullref, stackoverflow, async, dictcorrupt), CDB catches the
exception automatically.

For hang modes (linkedlist, deadlock) and OOM modes (eventleak, finalizerstall,
lohfrag), the script sends a Ctrl+Break to CDB after a delay to interrupt the
running target, then starts ChatDBG analysis.
"""

import argparse
import ctypes
import os
import signal
import shutil
import sys
import textwrap
import threading
import time

# Ensure stdout/stderr handle Unicode on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add ChatDBG source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from chatdbg.cdb_session import CDBSession

# ---------------------------------------------------------------------------
# Mode definitions
# ---------------------------------------------------------------------------

CRASH_MODES = ["nullref", "stackoverflow", "async", "dictcorrupt"]
HANG_MODES = ["linkedlist", "deadlock"]
OOM_MODES = ["eventleak", "finalizerstall", "lohfrag"]

ALL_MODES = CRASH_MODES + HANG_MODES + OOM_MODES

MODE_INFO = {
    "nullref":        "NullReferenceException (immediate crash)",
    "stackoverflow":  "StackOverflowException (immediate crash)",
    "async":          "InvalidOperationException from async Task",
    "dictcorrupt":    "InvalidOperationException from concurrent Dictionary writes",
    "linkedlist":     "Hang — infinite loop in cyclic linked list",
    "deadlock":       "Hang — ABBA deadlock between two threads",
    "eventleak":      "OOM — event handler subscribers never unsubscribed",
    "finalizerstall": "OOM — finalizer thread blocked by Sleep(Infinite)",
    "lohfrag":        "OOM — Large Object Heap fragmentation",
}

# How long to let hang/OOM modes run before breaking in
HANG_DELAY = 5      # seconds for hang modes
OOM_DELAY = 15       # seconds for OOM modes (need time to build up state)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_cdb():
    for name in ("cdb", "cdbX64.exe", "cdbX86.exe"):
        path = shutil.which(name)
        if path:
            return name
    # Common Windows SDK locations
    for p in [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
    ]:
        if os.path.exists(p):
            return p
    return "cdb"


def find_exe():
    """Find the built DotnetCrashSample.exe."""
    base = os.path.dirname(os.path.abspath(__file__))
    for config in ("Debug", "Release"):
        exe = os.path.join(base, "bin", config, "net8.0", "DotnetCrashSample.exe")
        if os.path.exists(exe):
            return exe
    raise FileNotFoundError("DotnetCrashSample.exe not found. Run 'dotnet build -c Debug' first.")


def send_break(proc, delay):
    """Send Ctrl+Break to CDB after a delay to interrupt the running target."""
    def _break():
        time.sleep(delay)
        if proc.poll() is None:
            try:
                # On Windows, CTRL_BREAK_EVENT goes to the process group
                os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
            except Exception as e:
                print(f"  [break] Failed to send break: {e}")
    t = threading.Thread(target=_break, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Run a single test
# ---------------------------------------------------------------------------

def run_test(mode, cdb_exe, exe_path, verbose=False):
    print(f"\n{'='*70}")
    print(f"  Mode: {mode}")
    print(f"  Expected: {MODE_INFO.get(mode, '?')}")
    print(f"{'='*70}")

    is_hang = mode in HANG_MODES
    is_oom = mode in OOM_MODES
    needs_break = is_hang or is_oom
    delay = HANG_DELAY if is_hang else OOM_DELAY if is_oom else 0

    # Build initial commands
    initial_commands = ["sxd e0434352"]  # suppress first-chance CLR exceptions

    if not needs_break:
        # Crash modes: just run to the crash
        initial_commands.append("g")

    print(f"  Launching CDB (break-in delay: {delay}s)..." if needs_break
          else "  Launching CDB (run to crash)...")

    try:
        if needs_break:
            # For hang/OOM modes, we need manual control over the break-in.
            # Create the session WITHOUT 'g' in initial_commands,
            # then send 'g' and break in after a delay.
            session = CDBSession(
                target_exe=exe_path,
                target_args=[mode],
                cdb_exe=cdb_exe,
                initial_commands=["sxd e0434352"],
            )

            # Send 'g' to start execution
            session._send("g")
            session._at_prompt.clear()
            with session._buf_lock:
                session._buf.clear()

            # Schedule break-in after delay
            send_break(session._proc, delay)

            # Wait for the break to happen
            if not session._at_prompt.wait(timeout=delay + 30):
                print("  [FAIL] CDB did not break within timeout")
                session.close()
                return False
            print(f"  CDB broke in after ~{delay}s")
        else:
            session = CDBSession(
                target_exe=exe_path,
                target_args=[mode],
                cdb_exe=cdb_exe,
                initial_commands=initial_commands,
            )
            print("  CDB caught exception")
    except TimeoutError as e:
        print(f"  [FAIL] CDB timeout: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] CDB launch failed: {e}")
        return False

    # Inject the session as a fake pykd module
    from chatdbg import cdb_proxy
    cdb_proxy._session = session
    sys.modules["pykd"] = cdb_proxy

    # Run ChatDBG analysis
    print("  Running ChatDBG analysis...")
    try:
        from chatdbg.chatdbg_windbg import chatdbg_windbg_init, WinDbgDialog

        chatdbg_windbg_init()
        dialog = WinDbgDialog("(test) ")
        dialog.dialog("")
        print(f"\n  [PASS] ChatDBG completed analysis for '{mode}'")
        result = True
    except Exception as e:
        print(f"\n  [FAIL] ChatDBG error: {e}")
        import traceback
        traceback.print_exc()
        result = False
    finally:
        session.close()

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="E2E test runner for DotnetCrashSample + ChatDBG")
    parser.add_argument("mode", nargs="?", help="Crash mode to test")
    parser.add_argument("--all", action="store_true", help="Run all modes")
    parser.add_argument("--list", action="store_true", help="List available modes")
    parser.add_argument("--cdb", default=None, help="Path to CDB executable")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.list:
        print("Available modes:")
        for mode in ALL_MODES:
            tag = "CRASH" if mode in CRASH_MODES else "HANG" if mode in HANG_MODES else "OOM"
            print(f"  {mode:20s} [{tag:5s}] {MODE_INFO[mode]}")
        return 0

    cdb_exe = args.cdb or find_cdb()
    exe_path = find_exe()
    print(f"CDB: {cdb_exe}")
    print(f"Target: {exe_path}")

    modes = ALL_MODES if args.all else [args.mode] if args.mode else None
    if not modes:
        parser.error("specify a mode, --all, or --list")

    results = {}
    for mode in modes:
        if mode not in ALL_MODES:
            print(f"Unknown mode: {mode}")
            results[mode] = False
            continue
        results[mode] = run_test(mode, cdb_exe, exe_path, args.verbose)

    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print(f"{'='*70}")
    for mode, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {mode}")

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} tests passed")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main() or 0)
