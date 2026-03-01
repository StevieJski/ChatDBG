import os
import re
import sys
import atexit
import types
from typing import List, Optional, Union

try:
    import pykd
except ImportError:
    pykd = None  # Allow import for testing with mock

from chatdbg.native_util import clangd_lsp_integration
from chatdbg.native_util.code import code
from chatdbg.native_util.dbg_dialog import DBGDialog, DBGError
from chatdbg.native_util.stacks import (
    _ArgumentEntry,
    _FrameSummaryEntry,
    _SkippedFramesEntry,
)
from chatdbg.util.config import chatdbg_config
from chatdbg.native_util.windbg_safety import windbg_command_is_safe
from chatdbg.util.exit_message import chatdbg_was_called, print_exit_message

PROMPT = "(ChatDBG windbg) "
_EXECUTION_STATUS_BREAK = 1  # pykd.executionStatus.Break
last_error_type = ""


def chatdbg_windbg_init():
    """Initialize ChatDBG when loaded into WinDbg/CDB."""
    instructions_path = os.path.join(
        os.path.dirname(__file__), "util", "instructions", "windbg.txt"
    )
    chatdbg_config.instructions = instructions_path
    atexit.register(print_exit_message)


def why_handler(args):
    try:
        dialog = WinDbgDialog(PROMPT)
        dialog.dialog(args)
    except Exception as e:
        print(str(e))


def chat_handler(args):
    why_handler(args)


def code_handler(args):
    print(code(args))


def config_handler(args):
    args_list = args.split() if args else []
    message = chatdbg_config.parse_only_user_flags(args_list)
    print(message)


class WinDbgDialog(DBGDialog):

    def __init__(self, prompt) -> None:
        chatdbg_was_called()
        super().__init__(prompt)
        self._is_dotnet = None  # Cached .NET detection
        self._is_ttd = None  # Cached TTD detection
        self._has_js_provider = None  # Cached JsProvider detection
        self._js_extension_tools = []
        self._load_js_extensions()

    def _run_one_command(self, command):
        try:
            return pykd.dbgCommand(command)
        except Exception as e:
            return str(e)

    def _message_is_a_bad_command_error(self, message):
        msg = message.strip().lower()
        return any(
            pattern in msg
            for pattern in [
                "no export",
                "couldn't resolve",
                "unknown command",
                "not found",
                "invalid command",
            ]
        )

    def check_debugger_state(self):
        try:
            status = pykd.getExecutionStatus()
            if status != _EXECUTION_STATUS_BREAK:
                self.fail(
                    "The debugger must be at a breakpoint or exception to use `why` or `chat`."
                )
        except DBGError:
            raise
        except Exception:
            self.fail("Must be attached to a program to use `why` or `chat`.")

        try:
            stack = pykd.getStack()
            if not stack:
                self.fail(
                    "Could not retrieve stack frames. Ensure the program has stopped at an error."
                )
        except DBGError:
            raise
        except Exception:
            self.fail(
                "Could not retrieve stack frames. Your program may need debug symbols."
            )

    def _get_frame_summaries(
        self, max_entries: int = 20
    ) -> Optional[List[Union[_FrameSummaryEntry, _SkippedFramesEntry]]]:
        try:
            stack = pykd.getStack()
        except Exception:
            return None

        if not stack:
            return None

        skipped = 0
        summaries: List[Union[_FrameSummaryEntry, _SkippedFramesEntry]] = []

        for index, frame in enumerate(stack):
            # Get symbol name
            try:
                symbol = pykd.findSymbol(frame.instructionOffset)
            except Exception:
                skipped += 1
                continue

            if not symbol or symbol == "":
                skipped += 1
                continue

            # Parse function name from "module!function+0xNN"
            name = symbol.split("+")[0] if "+" in symbol else symbol

            # Try to get source file and line via "ln" command
            file_path = None
            lineno = None
            try:
                ln_output = pykd.dbgCommand(f"ln {frame.instructionOffset:#x}")
                # Parse ln output for file:line pattern
                # Typical: "[d:\path\file.cpp @ 42]"
                match = re.search(r"\[(.+?)\s*@\s*(\d+)\]", ln_output)
                if not match:
                    # Alternate pattern: "d:\path\file.cpp(42)"
                    match = re.search(
                        r"(\S+\.(?:c|cpp|cxx|cc|h|hpp|cs))\((\d+)\)",
                        ln_output,
                        re.IGNORECASE,
                    )
                if match:
                    file_path = match.group(1)
                    lineno = int(match.group(2))
            except Exception:
                pass

            # Try to get arguments via dv /t
            arguments: List[_ArgumentEntry] = []
            try:
                pykd.dbgCommand(f".frame {index}")
                dv_output = pykd.dbgCommand("dv /t")
                if dv_output:
                    for line in dv_output.strip().split("\n"):
                        line = line.strip()
                        # Parse "type name = value" pattern (handles multi-pointer types like char **)
                        dv_match = re.match(
                            r"(\S+(?:\s*\*+)?)\s+(\w+)\s*=\s*(.*)", line
                        )
                        if dv_match:
                            arguments.append(
                                _ArgumentEntry(
                                    dv_match.group(1),
                                    dv_match.group(2),
                                    dv_match.group(3).strip(),
                                )
                            )
            except Exception:
                pass

            # Skip frames without source on disk
            if file_path and not os.path.exists(file_path):
                skipped += 1
                continue

            # Use relative path if in cwd
            if file_path and file_path.startswith(os.getcwd()):
                file_path = os.path.relpath(file_path)

            if skipped > 0:
                summaries.append(_SkippedFramesEntry(skipped))
                skipped = 0

            summaries.append(
                _FrameSummaryEntry(index, name, arguments, file_path, lineno)
            )
            if len(summaries) >= max_entries:
                break

        if skipped > 0:
            summaries.append(_SkippedFramesEntry(skipped))

        # Merge managed frames if .NET detected
        if self._detect_dotnet():
            self._merge_managed_frames(summaries)

        return summaries if summaries else None

    # ------------------------------------------------------------------
    # .NET and TTD detection
    # ------------------------------------------------------------------

    def _detect_dotnet(self):
        if self._is_dotnet is None:
            try:
                lm_output = pykd.dbgCommand("lm")
                self._is_dotnet = (
                    "clr" in lm_output.lower() or "coreclr" in lm_output.lower()
                )
            except Exception:
                self._is_dotnet = False
        return self._is_dotnet

    def _detect_ttd(self):
        if self._is_ttd is None:
            try:
                result = pykd.dbgCommand("dx @$curprocess.TTD")
                self._is_ttd = "Error" not in result and result.strip() != ""
            except Exception:
                self._is_ttd = False
        return self._is_ttd

    def _detect_jsprovider(self):
        if self._has_js_provider is None:
            try:
                output = pykd.dbgCommand(".scriptproviders")
                self._has_js_provider = (
                    output is not None and "javascript" in output.lower()
                )
            except Exception:
                self._has_js_provider = False
        return self._has_js_provider

    def _load_js_extensions(self):
        """Discover, load, and generate tool functions for JS extensions."""
        try:
            from chatdbg.windbg_js_extensions import (
                discover_js_extensions,
                load_js_extensions,
                make_tool_functions,
            )

            extensions = discover_js_extensions(
                self._run_one_command, chatdbg_config.js_extensions
            )
            if not extensions:
                return

            load_results = load_js_extensions(self._run_one_command, extensions)
            loaded = [
                ext for ext in extensions if load_results.get(ext["name"])
            ]
            self._js_extension_tools = make_tool_functions(loaded)
        except Exception:
            self._js_extension_tools = []

    def _merge_managed_frames(self, summaries):
        """Attempt to merge CLRStack frames into the native summary."""
        try:
            clrstack = pykd.dbgCommand("!CLRStack -p")
            if not clrstack:
                return
            # Parse managed frame lines: "SP  IP  Function"
            # e.g., "000000AB1234 000000CD5678 MyApp.Program.Main(System.String[])"
            for line in clrstack.strip().split("\n"):
                match = re.match(
                    r"\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)", line
                )
                if match and not line.strip().startswith(
                    "SP"
                ) and not line.strip().startswith("OS"):
                    # These frames provide context but don't replace native frames.
                    # They are informational in the stack output.
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Prompt methods
    # ------------------------------------------------------------------

    _ANALYZE_MAX_CHARS = 2048

    def _initial_prompt_error_message(self):
        try:
            analyze = pykd.dbgCommand("!analyze -v")
            if analyze:
                return analyze[:self._ANALYZE_MAX_CHARS]
        except Exception:
            pass
        return last_error_type if last_error_type else "Unknown error"

    def _initial_prompt_error_details(self):
        try:
            ecxr = pykd.dbgCommand(".ecxr")
            if ecxr and "not stored" not in ecxr.lower():
                return ecxr
        except Exception:
            pass
        return None

    def _initial_prompt_command_line(self):
        try:
            peb_output = pykd.dbgCommand("!peb")
            if peb_output:
                for line in peb_output.split("\n"):
                    if "CommandLine:" in line:
                        return line.split("CommandLine:")[1].strip().strip("'\"")
        except Exception:
            pass
        return None

    def _initial_prompt_input(self):
        cmd_line = self._initial_prompt_command_line()
        if cmd_line:
            input_pipe = cmd_line.find("<")
            if input_pipe != -1:
                input_file = cmd_line[input_pipe + 1 :].strip()
                try:
                    content = open(input_file, "r").read()
                    return content
                except Exception:
                    self.fail(
                        f"The detected input file {input_file} could not be read."
                    )
        return None

    def _prompt_stack(self):
        try:
            return pykd.dbgCommand("k 20")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # LLM tool functions
    # ------------------------------------------------------------------

    def llm_debug(self, command: str):
        """
        {
            "name": "debug",
            "description": "The `debug` function runs a WinDbg/CDB command on the stopped program and gets the response. Useful WinDbg commands include: 'k' (stack trace), 'dv' (local variables), 'dt <type> <addr>' (display type), 'dx <expr>' (evaluate expression), '!analyze -v' (crash analysis), 'r' (registers), 'u <addr>' (disassemble), 'db/dd/dq <addr>' (memory display), 'ln <addr>' (nearest symbol), '.frame <n>' (select frame), 'x <pattern>' (search symbols).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The WinDbg command to run, possibly with arguments."
                    }
                },
                "required": [ "command" ]
            }
        }
        """
        if not chatdbg_config.unsafe and not windbg_command_is_safe(command):
            self._unsafe_cmd = True
            return command, f"Command `{command}` is not allowed."
        return command, self._run_one_command(command)

    def _supported_functions(self):
        functions = [self.llm_debug, self.llm_get_code_surrounding]
        if clangd_lsp_integration.is_available():
            functions.append(self.llm_find_definition)

        # Add TTD tools if TTD trace detected
        if self._detect_ttd():
            from chatdbg.windbg_tools import TTD_TOOLS

            for tool_func in TTD_TOOLS:
                functions.append(types.MethodType(tool_func, self))

        # Add .NET/SOS tools if CLR detected
        if self._detect_dotnet():
            from chatdbg.windbg_tools import DOTNET_TOOLS

            for tool_func in DOTNET_TOOLS:
                functions.append(types.MethodType(tool_func, self))

        # Add JS extension tools if any were loaded
        if self._js_extension_tools:
            for tool_func in self._js_extension_tools:
                functions.append(types.MethodType(tool_func, self))

        # Add JS scripting tool if JsProvider is available
        if self._detect_jsprovider():
            from chatdbg.windbg_js_scripting import JS_SCRIPTING_TOOLS

            for tool_func in JS_SCRIPTING_TOOLS:
                functions.append(types.MethodType(tool_func, self))

        return functions


# When loaded as a script in WinDbg via: !py -g "<path>/chatdbg_windbg.py"
# pykd sets __name__ to "__main__". When imported as a module for testing,
# __name__ will be the module path, so this block won't execute.
if __name__ == "__main__":
    chatdbg_windbg_init()
    if len(sys.argv) > 1:
        why_handler(" ".join(sys.argv[1:]))
    else:
        why_handler("")
