"""
Mock PyKD module that simulates pykd functions for testing WinDbgDialog
on any platform without WinDbg installed.

Usage:
    import sys
    from tests.mock_pykd import MockPyKD
    mock = MockPyKD(scenario="native_crash")
    sys.modules["pykd"] = mock
"""

import os
import re


class MockStackFrame:
    """Simulates a pykd stack frame object."""

    def __init__(self, instruction_offset, return_offset=0, frame_number=0):
        self.instructionOffset = instruction_offset
        self.returnOffset = return_offset
        self.frameNumber = frame_number


# Execution status constants (mirrors pykd.executionStatus)
EXECUTION_STATUS_BREAK = 1
EXECUTION_STATUS_GO = 0


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "windbg")


def _load_fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return ""


# Preloaded fixture data
_FIXTURES = {
    "k 20": _load_fixture("k_output.txt"),
    "!analyze -v": _load_fixture("analyze_v_output.txt"),
    "!CLRStack -a": _load_fixture("clrstack_output.txt"),
    "!CLRStack -p": _load_fixture("clrstack_output.txt"),
    "!DumpObj": _load_fixture("dumpobj_output.txt"),
    "!DumpStackObjects": _load_fixture("dumpstackobjects_output.txt"),
    "!peb": _load_fixture("peb_output.txt"),
    ".ecxr": _load_fixture("ecxr_output.txt"),
    "dv /t": _load_fixture("dv_output.txt"),
    "lm": "start             end                 module name\n"
          "00007ff7`12340000 00007ff7`12350000   crash_sample   (deferred)\n"
          "00007ff8`23450000 00007ff8`23550000   KERNEL32   (deferred)\n"
          "00007ff8`34560000 00007ff8`34750000   ntdll      (deferred)\n",
}

# Symbols by instruction offset
_SYMBOLS = {
    0x00007FF712340015: "crash_sample!main+0x15",
    0x00007FF812345678: "crash_sample!__scrt_common_main_seh+0x10c",
    0x00007FF823456789: "KERNEL32!BaseThreadInitThunk+0x1d",
    0x00007FF83456789A: "ntdll!RtlUserThreadCallbackDispatcher+0x4e",
}


class MockPyKD:
    """Mock pykd module supporting multiple scenarios."""

    def __init__(self, scenario="native_crash"):
        self.scenario = scenario
        self._execution_status = EXECUTION_STATUS_BREAK
        self._command_log = []
        self._custom_responses = {}

        # Build scenario-specific fixtures
        self._fixtures = dict(_FIXTURES)
        if scenario == "js_extensions":
            self._fixtures[".scriptproviders"] = (
                "Available Script Providers:\n"
                "    NatVis (NatVis Visualizer)\n"
                "    JavaScript (JsProvider)\n"
            )
            self._fixtures[".scriptlist"] = (
                "Loaded Script List:\n"
                "    (none)\n"
            )
        elif scenario == "dotnet_crash":
            self._fixtures["lm"] = (
                "start             end                 module name\n"
                "00007ff7`12340000 00007ff7`12350000   DotnetCrash   (deferred)\n"
                "00007ff8`10000000 00007ff8`10500000   coreclr   (deferred)\n"
                "00007ff8`23450000 00007ff8`23550000   KERNEL32   (deferred)\n"
            )
        elif scenario == "ttd_trace":
            self._fixtures["dx @$curprocess.TTD"] = (
                "@$curprocess.TTD\n"
                "    Lifetime         : [0:0, 50:0]\n"
                "    Threads\n"
                "    Events\n"
            )
            self._fixtures['dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception")'] = (
                _load_fixture("ttd_exceptions_output.txt")
            )

    def set_response(self, command, response):
        """Set a custom response for a specific command."""
        self._custom_responses[command] = response

    def dbgCommand(self, command):
        """Simulate pykd.dbgCommand()."""
        self._command_log.append(command)

        # Check custom responses first
        if command in self._custom_responses:
            return self._custom_responses[command]

        # Check exact match
        if command in self._fixtures:
            return self._fixtures[command]

        # Check prefix match for commands with arguments
        for key in self._fixtures:
            if command.startswith(key):
                return self._fixtures[key]

        # Handle ln commands — return source path that exists on disk
        if command.startswith("ln "):
            sample_path = os.path.join(
                os.path.dirname(__file__), "..", "samples", "windbg", "crash_sample.c"
            )
            sample_path = os.path.normpath(sample_path)
            return (
                f"(00007ff7`12340015)   crash_sample!main+0x15\n"
                f"Exact matches:\n"
                f"    [{sample_path} @ 10]\n"
            )

        # Handle .frame commands
        if command.startswith(".frame"):
            return ""

        # Handle .scriptload commands
        if command.startswith(".scriptload"):
            if self.scenario == "js_extensions":
                return "JavaScript script successfully loaded."
            return ""

        # Handle TTD dx command when not in TTD scenario
        if "TTD" in command and self.scenario != "ttd_trace":
            raise Exception("Error: unable to resolve")

        # Default
        return ""

    def getStack(self):
        """Simulate pykd.getStack()."""
        return [
            MockStackFrame(0x00007FF712340015, 0x00007FF812345678, 0),
            MockStackFrame(0x00007FF812345678, 0x00007FF823456789, 1),
            MockStackFrame(0x00007FF823456789, 0x00007FF83456789A, 2),
            MockStackFrame(0x00007FF83456789A, 0, 3),
        ]

    def findSymbol(self, address):
        """Simulate pykd.findSymbol()."""
        return _SYMBOLS.get(address, f"unknown!func+0x{address:x}")

    def getExecutionStatus(self):
        """Simulate pykd.getExecutionStatus()."""
        return self._execution_status

    def set_execution_status(self, status):
        """Test helper to change execution status."""
        self._execution_status = status

    def get_command_log(self):
        """Test helper to retrieve all commands run."""
        return list(self._command_log)

    def clear_command_log(self):
        """Test helper to clear command log."""
        self._command_log.clear()
