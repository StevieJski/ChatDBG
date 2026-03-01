"""
LLM-generated JavaScript execution for WinDbg/CDB.

Provides a `run_js` tool that lets the LLM write and execute custom JavaScript
inside CDB's JsProvider. The full lifecycle is:

  1. Safety-scan the code for dangerous patterns (unless --unsafe)
  2. Wrap code in a JS template with a run() function
  3. Write to a temp .js file
  4. .scriptload the temp file
  5. dx @$scriptContents.run() — capture output
  6. .scriptunload the temp file
  7. Delete the temp file
  8. Return output to the LLM

This module follows the windbg_tools.py pattern: each function takes `self`
(a WinDbgDialog instance) and calls `self._run_one_command()` directly,
bypassing the safety filter.
"""

import os
import re
import tempfile


# ---------------------------------------------------------------------------
# JS template
# ---------------------------------------------------------------------------

_JS_TEMPLATE = '''\
"use strict";

function run() {{
{code}
}}
'''


# ---------------------------------------------------------------------------
# Safety check
# ---------------------------------------------------------------------------

# Patterns that indicate dangerous operations. Defense-in-depth only —
# not a hard security boundary. Bypassed by --unsafe.
_DANGEROUS_PATTERNS = [
    # Memory writes via ExecuteCommand
    (r'ExecuteCommand\s*\(\s*["\']e[bwd]\s', "memory write (eb/ew/ed)"),
    # Execution resume commands
    (r'ExecuteCommand\s*\(\s*["\'](?:g|p|t)\s*["\']', "execution resume (g/p/t)"),
    # Register writes
    (r'ExecuteCommand\s*\(\s*["\']r\s+\w+=', "register write (r reg=)"),
    # Kill / detach
    (r'ExecuteCommand\s*\(\s*["\']\.kill', "kill target (.kill)"),
    (r'ExecuteCommand\s*\(\s*["\']\.detach', "detach target (.detach)"),
    # Direct host.namespace calls that modify state
    (r'ExecuteCommand\s*\(\s*["\']\.restart', "restart target (.restart)"),
    (r'ExecuteCommand\s*\(\s*["\']bp\s', "set breakpoint (bp)"),
]

_COMPILED_PATTERNS = [(re.compile(pat, re.IGNORECASE), desc) for pat, desc in _DANGEROUS_PATTERNS]


def _check_js_safety(code):
    """Scan JS code for dangerous patterns.

    Returns:
        None if safe, or a string describing the first dangerous pattern found.
    """
    for pattern, description in _COMPILED_PATTERNS:
        if pattern.search(code):
            return description
    return None


# ---------------------------------------------------------------------------
# Tool function
# ---------------------------------------------------------------------------


def llm_run_js(self, code: str):
    """
    {
        "name": "run_js",
        "description": "Execute custom JavaScript code inside CDB's JsProvider for multi-step analysis. Write the function body (not the function declaration) — it will be wrapped in a run() function automatically. Use `return` to send results back. Available APIs: host.currentProcess, host.currentThread, host.currentSession, host.memory, host.parseInt64(), host.namespace.Debugger, host.diagnostics.debugLog(). Use host.namespace.Debugger.Utility.Control.ExecuteCommand() to run CDB commands and capture output. Write read-only analysis code only.",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "The JavaScript function body to execute. Will be wrapped in function run() { ... }. Use 'return' to produce output."
                }
            },
            "required": [ "code" ]
        }
    }
    """
    from chatdbg.util.config import chatdbg_config

    # 1. Safety scan (unless --unsafe)
    if not chatdbg_config.unsafe:
        violation = _check_js_safety(code)
        if violation:
            return "run_js [blocked]", f"Code blocked by safety check: {violation}. Use --unsafe to bypass."

    # 2. Wrap code in JS template
    # Indent each line of user code by 4 spaces for clean formatting
    indented = "\n".join("    " + line for line in code.splitlines())
    js_content = _JS_TEMPLATE.format(code=indented)

    # 3. Write to temp file
    fd, tmp_path = tempfile.mkstemp(suffix=".js", prefix="chatdbg_js_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(js_content)

        # 4. .scriptload
        load_output = self._run_one_command(f'.scriptload "{tmp_path}"')
        if load_output and any(
            err in load_output.lower()
            for err in ["error", "failed", "cannot", "unable"]
        ):
            return f'.scriptload "{tmp_path}"', f"Script load failed:\n{load_output}"

        # 5. dx @$scriptContents.run()
        try:
            output = self._run_one_command("dx @$scriptContents.run()")
        except Exception as e:
            output = f"Error executing script: {e}"

        # 6. .scriptunload
        try:
            self._run_one_command(f'.scriptunload "{tmp_path}"')
        except Exception:
            pass  # Best-effort cleanup

        return "run_js", output

    finally:
        # 7. Delete temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Export list for registration
# ---------------------------------------------------------------------------

JS_SCRIPTING_TOOLS = [llm_run_js]
