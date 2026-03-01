"""
ChatDBG CDB entry point — launches CDB as a subprocess, injects a fake
``pykd`` module backed by CDB stdin/stdout, then runs the standard
ChatDBG WinDbg dialog.

Usage::

    py -3.12 -m chatdbg.chatdbg_cdb crash_sample.exe [args...]
    py -3.12 -m chatdbg.chatdbg_cdb --dotnet DotnetCrashSample.exe nullref
    py -3.12 -m chatdbg.chatdbg_cdb -z crash.dmp
"""

import argparse
import shutil
import sys


def _find_cdb():
    """Find CDB on PATH, trying 'cdb' first then the WinDbg Store name."""
    for name in ("cdb", "cdbX64.exe", "cdbX86.exe"):
        path = shutil.which(name)
        if path:
            return name
    return "cdb"  # fall back and let the OS error explain what's missing


def main():
    parser = argparse.ArgumentParser(
        prog="chatdbg_cdb",
        description="ChatDBG: AI-assisted debugging via CDB subprocess",
    )
    parser.add_argument(
        "--dotnet",
        action="store_true",
        help="Target is a .NET application (ignore first-chance CLR exceptions)",
    )
    parser.add_argument(
        "-z",
        "--dump",
        metavar="DMPFILE",
        help="Open a crash dump file instead of a live target",
    )
    parser.add_argument(
        "--cdb",
        default=None,
        metavar="PATH",
        help="Path to the CDB executable (default: auto-detect)",
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target executable to debug",
    )
    parser.add_argument(
        "target_args",
        nargs=argparse.REMAINDER,
        help="Arguments to the target executable",
    )

    args = parser.parse_args()

    if not args.target and not args.dump:
        parser.error("either a target executable or -z <dump file> is required")

    # Filter out '--' separator that argparse.REMAINDER may capture
    target_args = [a for a in args.target_args if a != "--"] or None

    # Build the list of initial CDB commands to run before handing off
    initial_commands = []

    if args.dotnet:
        # Suppress first-chance CLR exceptions (0xe0434352 = CLR exception code)
        initial_commands.append("sxd e0434352")

    if not args.dump:
        # For live targets, run to the crash/exception
        initial_commands.append("g")

    cdb_exe = args.cdb or _find_cdb()

    # Import cdb_proxy and inject it as 'pykd' BEFORE importing chatdbg_windbg,
    # because chatdbg_windbg does `import pykd` at module load time.
    from chatdbg import cdb_proxy

    sys.modules["pykd"] = cdb_proxy

    # Launch CDB
    try:
        cdb_proxy.init(
            target_exe=args.target,
            target_args=target_args,
            cdb_exe=cdb_exe,
            initial_commands=initial_commands,
            dump_file=args.dump,
        )
    except Exception as e:
        print(f"[ChatDBG] Failed to launch CDB: {e}", file=sys.stderr)
        return 1

    # Now import and run the standard WinDbg ChatDBG flow
    from chatdbg.chatdbg_windbg import chatdbg_windbg_init, why_handler

    chatdbg_windbg_init()
    why_handler("")

    # Clean up
    cdb_proxy.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
