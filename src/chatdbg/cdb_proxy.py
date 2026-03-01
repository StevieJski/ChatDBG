"""
Fake ``pykd`` module that wraps a CDBSession subprocess.

Injected into ``sys.modules["pykd"]`` by ``chatdbg_cdb.py`` so that
``chatdbg_windbg.py`` can ``import pykd`` and call the same 4-function API
it expects — but everything goes through CDB's stdin/stdout instead of the
real pykd extension.
"""

import re

from chatdbg.cdb_session import CDBSession

# ---------------------------------------------------------------------------
# Module-level session (initialised by init())
# ---------------------------------------------------------------------------

_session = None


def init(target_exe=None, target_args=None, cdb_exe="cdb",
         initial_commands=None, dump_file=None):
    """
    Launch CDB and prepare the session.  Must be called once before any
    other function in this module.
    """
    global _session
    _session = CDBSession(
        target_exe=target_exe,
        target_args=target_args,
        cdb_exe=cdb_exe,
        initial_commands=initial_commands,
        dump_file=dump_file,
    )


def shutdown():
    """Terminate the CDB subprocess."""
    global _session
    if _session is not None:
        _session.close()
        _session = None


# ---------------------------------------------------------------------------
# pykd-compatible public API
# ---------------------------------------------------------------------------


def dbgCommand(command):
    """Run a debugger command and return its text output."""
    if _session is None:
        raise RuntimeError("cdb_proxy not initialised — call init() first")
    return _session.execute(command)


def getExecutionStatus():
    """
    Return the debugger execution status.

    1 = Break (the debugger is stopped at a prompt).
    0 = running / not available.
    """
    if _session is None:
        return 0
    return 1 if _session.is_alive else 0


class _StackFrame:
    """Lightweight stand-in for pykd.stackFrame."""

    def __init__(self, instruction_offset, return_offset=0,
                 frame_offset=0, stack_offset=0):
        self.instructionOffset = instruction_offset
        self.returnOffset = return_offset
        self.frameOffset = frame_offset
        self.stackOffset = stack_offset


def getStack():
    """
    Return a list of stack-frame objects by executing ``kn`` in CDB and
    parsing the output.

    CDB ``kn`` output looks like::

        # Child-SP          RetAddr               Call Site
        00 000000ab`1234abcd 00007ff6`12345678     module!function+0x12
        01 000000ab`1234abce 00007ff6`12345679     module!other+0x34

    For frame 0 the instruction pointer is fetched separately via the
    ``r $ip`` register so we get the exact crash address rather than
    using the return address.
    """
    if _session is None:
        raise RuntimeError("cdb_proxy not initialised — call init() first")

    raw = _session.execute("kn")
    frames = []

    for line in raw.splitlines():
        line = line.strip()
        # Match frame lines: "NN hex hex symbol"
        m = re.match(
            r"([0-9a-fA-F]+)\s+"          # frame number
            r"([0-9a-fA-F`]+)\s+"          # Child-SP / stack offset
            r"([0-9a-fA-F`]+)\s+"          # RetAddr
            r"(\S+)",                       # Call Site (symbol)
            line,
        )
        if m:
            frame_num = int(m.group(1), 16)
            stack_off = int(m.group(2).replace("`", ""), 16)
            ret_addr = int(m.group(3).replace("`", ""), 16)
            frames.append(_StackFrame(
                instruction_offset=ret_addr,
                return_offset=ret_addr,
                frame_offset=0,
                stack_offset=stack_off,
            ))

    # For frame 0, use the actual instruction pointer instead of return addr
    if frames:
        try:
            ip_raw = _session.execute("r $ip")
            # Output like "rip=00007ff6`12345678" or "eip=12345678"
            ip_match = re.search(r"=\s*([0-9a-fA-F`]+)", ip_raw)
            if ip_match:
                frames[0].instructionOffset = int(
                    ip_match.group(1).replace("`", ""), 16
                )
        except Exception:
            pass

    return frames


def findSymbol(offset):
    """
    Resolve an address to a symbol name using ``ln <offset>``.

    Returns the nearest symbol string (e.g. ``module!function+0x12``),
    or an empty string if resolution fails.
    """
    if _session is None:
        raise RuntimeError("cdb_proxy not initialised — call init() first")

    raw = _session.execute(f"ln {offset:#x}")

    # ``ln`` output typically contains lines like:
    #   (00007ff6`12345600)   module!function+0x12   |  ...
    # We capture the symbol with its optional +offset suffix.
    for line in raw.splitlines():
        m = re.search(r"\)\s+(\S+!\S+?)(?:\s|$)", line)
        if m:
            return m.group(1)

    return ""
