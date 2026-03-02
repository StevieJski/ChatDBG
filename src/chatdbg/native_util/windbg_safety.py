import re


# Whitelist-based safety checking for WinDbg commands.
# WinDbg commands are case-insensitive, so we normalize to lowercase.
# If ChatDBG wants to call other commands not listed here, they should be
# evaluated and added if not possibly harmful.
def windbg_command_is_safe(cmd: str) -> bool:
    cmd = cmd.strip()
    if not cmd:
        return False

    command_name = cmd.split()[0].lower()

    # Allowed unconditionally: read-only commands.
    if command_name in [
        # Stack
        "k", "kb", "kp", "kn", "kv", "kd", "kc",
        # Frame
        ".frame",
        # Modules and symbols
        "lm", "x", "ln",
        # Disassembly
        "u", "uf", "ub",
        # Variables and types
        "dv", "dt",
        # Memory display
        "db", "dw", "dd", "dq", "dp", "da", "du",
        # Analysis
        "!analyze", ".ecxr", ".exr", ".lastevent",
        # SOS / CLR diagnostics
        "!clrstack", "!dumpobj", "!dumpstackobjects", "!dumpheap",
        "!dumpmt", "!name2ee", "!eestack", "!threads", "!gcroot", "!pe",
        "!syncblk", "!finalizequeue", "!dumparray", "!threadpool",
        "!dumpasync", "!dumpvc", "!dumpdomain", "!dumpmodule",
        # TTD
        "!tt", "!positions",
        # Info
        "version", "vertarget", "!peb", "!teb",
        # Script provider queries (read-only)
        ".scriptproviders", ".scriptlist",
    ]:
        return True

    # Allowed conditionally: evaluate expression.
    # Restrict to simple variable/register expressions.
    if command_name == "?":
        args = cmd[1:].strip()
        return re.fullmatch(r"[\w@$+\-*/() .]+", args) is not None

    # 'r' (registers): allow read-only forms, block writes (r reg=value).
    if command_name == "r":
        args = cmd[len(cmd.split()[0]):].strip()
        return "=" not in args

    # 'dx' (expression evaluator): allow property/member traversal only.
    # Block method calls, assignments, and complex expressions that could
    # have side effects (e.g., dx Debugger.Sessions.First().Terminate()).
    if command_name == "dx":
        args = cmd[len(cmd.split()[0]):].strip()
        return re.fullmatch(r"[\w@$.\[\] ]+", args) is not None

    return False
