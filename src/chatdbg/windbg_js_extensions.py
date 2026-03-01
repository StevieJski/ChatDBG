"""
WinDbg JavaScript extension integration.

Discovers, loads, and generates tool functions for WinDbg JavaScript extensions
(JsProvider.dll). Each JS extension function gets a dedicated Python tool with
a JSON schema docstring, following the same pattern as TTD and .NET tools in
windbg_tools.py.

The tool functions call `self._run_one_command()` directly (bypassing the safety
filter), while the safety filter on `llm_debug()` continues to block raw `dx`
calls with parentheses — the LLM must use the dedicated tools.
"""

import json
import os
import re


# ---------------------------------------------------------------------------
# Extension registry
# ---------------------------------------------------------------------------

JS_EXTENSION_REGISTRY = [
    {
        "name": "lldext",
        "script_paths": ["lldext/lldext.js", "lldext.js"],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "analyze",
                "tool_name": "js_lldext_analyze",
                "description": "Run lldext full analysis on the current debug target. Provides function discovery, call path analysis, and TTD-aware diagnostics.",
                "parameters": {},
            },
            {
                "js_func": "callpath",
                "tool_name": "js_lldext_callpath",
                "description": "Trace the call path to the current position using lldext. Shows how execution reached the current point.",
                "parameters": {},
            },
            {
                "js_func": "funcdiscover",
                "tool_name": "js_lldext_funcdiscover",
                "description": "Discover functions in the current module using lldext. Lists functions with entry points and sizes.",
                "parameters": {},
            },
        ],
    },
    {
        "name": "WinDbgCookbook",
        "script_paths": [
            "WinDbgCookbook/StackCorruptionDetection.js",
            "StackCorruptionDetection.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "detectStackCorruption",
                "tool_name": "js_detect_stack_corruption",
                "description": "Detect stack corruption by analyzing stack frames for inconsistencies, overwritten return addresses, and canary violations.",
                "parameters": {},
            },
        ],
    },
    {
        "name": "WinDbgCookbook_CallGraph",
        "script_paths": [
            "WinDbgCookbook/CallGraph.js",
            "CallGraph.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "collectCallGraph",
                "tool_name": "js_collect_call_graph",
                "description": "Collect and display the call graph for the current execution context. Shows function call relationships.",
                "parameters": {},
            },
        ],
    },
    {
        "name": "telescope",
        "script_paths": [
            "windbg-scripts/telescope/telescope.js",
            "telescope.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "telescope",
                "tool_name": "js_telescope",
                "description": "GEF-style memory telescope. Recursively dereferences pointers from a given address, showing the chain of values. Useful for exploring stack and heap layouts.",
                "parameters": {
                    "address": {
                        "type": "string",
                        "description": "Memory address to telescope from (e.g., '@rsp', '0x7ffe1234').",
                    },
                },
                "required": ["address"],
            },
        ],
    },
    {
        "name": "codeCoverage",
        "script_paths": [
            "windbg-scripts/codecoverage/TTDcodecoverage.js",
            "TTDcodecoverage.js",
        ],
        "namespace": "@$scriptContents",
        "tools": [
            {
                "js_func": "codeCoverage",
                "tool_name": "js_ttd_code_coverage",
                "description": "Compute code coverage from a TTD (Time Travel Debugging) trace. Shows which functions and code blocks were executed during the recording.",
                "parameters": {},
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Argument formatting
# ---------------------------------------------------------------------------


def _format_js_arg(value):
    """Format a Python value for use in a WinDbg dx JS function call.

    Strings are quoted, numbers and booleans pass through as-is.
    """
    if isinstance(value, str):
        # Escape backslashes and double-quotes inside the string
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    # Fallback: stringify
    return str(value)


def _format_js_args(params_spec, kwargs):
    """Build the argument list string for a JS function call.

    Args:
        params_spec: dict of param_name -> {"type": ...} from the tool definition
        kwargs: actual keyword arguments passed by the LLM

    Returns:
        A string like '"hello", 42' ready to paste between parentheses.
    """
    if not params_spec:
        return ""
    parts = []
    for name in params_spec:
        if name in kwargs:
            parts.append(_format_js_arg(kwargs[name]))
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

# Standard locations where WinDbg JS extensions might be installed
_STANDARD_SEARCH_DIRS = [
    # WinDbg extension directories
    os.path.expandvars(r"%LOCALAPPDATA%\DBG\Scripts"),
    os.path.expandvars(r"%LOCALAPPDATA%\DBG\Extensions"),
    # Common manual install locations
    os.path.expandvars(r"%USERPROFILE%\Documents\WinDbg Scripts"),
    os.path.expandvars(r"%PROGRAMFILES%\Windows Kits\10\Debuggers\x64\winext"),
]


def discover_js_extensions(run_command_fn, config_paths=""):
    """Discover available JS extensions.

    Args:
        run_command_fn: callable that executes a WinDbg command (pykd.dbgCommand)
        config_paths: semicolon-separated extra search paths from config

    Returns:
        List of dicts: [{"name": ..., "script_path": ..., "namespace": ..., "tools": [...]}]
        Empty list if JsProvider is not available.
    """
    # 1. Check if JsProvider is available
    try:
        providers_output = run_command_fn(".scriptproviders")
    except Exception:
        return []

    if not providers_output or "javascript" not in providers_output.lower():
        return []

    # 2. Build search directories list
    search_dirs = []
    if config_paths:
        search_dirs.extend(
            d.strip() for d in config_paths.split(";") if d.strip()
        )
    search_dirs.extend(_STANDARD_SEARCH_DIRS)

    # 3. Find extensions
    available = []
    for ext in JS_EXTENSION_REGISTRY:
        resolved_path = _find_script(ext["script_paths"], search_dirs)
        if resolved_path:
            available.append(
                {
                    "name": ext["name"],
                    "script_path": resolved_path,
                    "namespace": ext["namespace"],
                    "tools": ext["tools"],
                }
            )

    return available


def _find_script(relative_paths, search_dirs):
    """Search for a JS script file in the given directories.

    Args:
        relative_paths: list of relative paths to try (e.g., ["lldext/lldext.js", "lldext.js"])
        search_dirs: list of directories to search in

    Returns:
        Absolute path if found, None otherwise.
    """
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for rel_path in relative_paths:
            full_path = os.path.join(search_dir, rel_path)
            if os.path.isfile(full_path):
                return full_path
    return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_js_extensions(run_command_fn, extensions):
    """Load discovered JS extensions into WinDbg.

    Args:
        run_command_fn: callable that executes a WinDbg command
        extensions: list from discover_js_extensions()

    Returns:
        Dict of extension name -> True/False (success/failure).
    """
    results = {}
    for ext in extensions:
        script_path = ext["script_path"]
        try:
            output = run_command_fn(f'.scriptload "{script_path}"')
            # Check for error indicators in output
            if output and any(
                err in output.lower()
                for err in ["error", "failed", "cannot", "unable"]
            ):
                results[ext["name"]] = False
            else:
                results[ext["name"]] = True
        except Exception:
            results[ext["name"]] = False
    return results


# ---------------------------------------------------------------------------
# Tool function factory
# ---------------------------------------------------------------------------


def make_js_tool_function(ext_name, namespace, js_func, tool_name, description, params, required=None):
    """Generate a tool function for a JS extension function.

    Returns a function with JSON schema docstring that can be bound to
    a WinDbgDialog instance via types.MethodType.

    The generated function calls self._run_one_command() directly
    (bypassing the safety filter), following the same pattern as
    TTD tools in windbg_tools.py.
    """
    if required is None:
        required = list(params.keys()) if params else []

    # Build JSON schema for the docstring
    schema = {
        "name": tool_name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": {p: params[p] for p in params},
            "required": required,
        },
    }
    schema_str = json.dumps(schema, indent=4)

    # Build the actual function
    def tool_function(self, **kwargs):
        args_str = _format_js_args(params, kwargs)
        cmd = f"dx {namespace}.{js_func}({args_str})"
        try:
            output = self._run_one_command(cmd)
        except Exception as e:
            return cmd, f"Error calling {ext_name}.{js_func}: {e}"
        return cmd, output

    # Set metadata
    tool_function.__name__ = tool_name
    tool_function.__qualname__ = tool_name
    tool_function.__doc__ = schema_str

    # Set parameter annotations for the function signature so the
    # Assistant can parse arguments correctly
    import inspect

    # Build a proper signature with **kwargs expanded to named params
    params_list = [inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    for p_name, p_spec in params.items():
        default = inspect.Parameter.empty
        params_list.append(
            inspect.Parameter(p_name, inspect.Parameter.KEYWORD_ONLY, default=default)
        )
    tool_function.__signature__ = inspect.Signature(params_list)

    return tool_function


def make_tool_functions(extensions):
    """Generate all tool functions for a list of loaded extensions.

    Args:
        extensions: list from discover_js_extensions(), filtered to
                    only those that loaded successfully.

    Returns:
        List of tool functions ready to be bound with types.MethodType.
    """
    tools = []
    for ext in extensions:
        for tool_def in ext["tools"]:
            func = make_js_tool_function(
                ext_name=ext["name"],
                namespace=ext["namespace"],
                js_func=tool_def["js_func"],
                tool_name=tool_def["tool_name"],
                description=tool_def["description"],
                params=tool_def.get("parameters", {}),
                required=tool_def.get("required"),
            )
            tools.append(func)
    return tools
