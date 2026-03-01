"""
Unit tests for WinDbg JavaScript extension integration.
"""

import json
import os
import sys
import tempfile
import pytest
from unittest.mock import MagicMock

from chatdbg.windbg_js_extensions import (
    _format_js_arg,
    _format_js_args,
    discover_js_extensions,
    load_js_extensions,
    make_js_tool_function,
    make_tool_functions,
    JS_EXTENSION_REGISTRY,
)


# ---------------------------------------------------------------------------
# _format_js_arg
# ---------------------------------------------------------------------------


class TestFormatJsArg:
    def test_string(self):
        assert _format_js_arg("hello") == '"hello"'

    def test_string_with_quotes(self):
        assert _format_js_arg('say "hi"') == '"say \\"hi\\""'

    def test_string_with_backslash(self):
        assert _format_js_arg("C:\\path") == '"C:\\\\path"'

    def test_integer(self):
        assert _format_js_arg(42) == "42"

    def test_float(self):
        assert _format_js_arg(3.14) == "3.14"

    def test_bool_true(self):
        assert _format_js_arg(True) == "true"

    def test_bool_false(self):
        assert _format_js_arg(False) == "false"

    def test_zero(self):
        assert _format_js_arg(0) == "0"


# ---------------------------------------------------------------------------
# _format_js_args
# ---------------------------------------------------------------------------


class TestFormatJsArgs:
    def test_empty_params(self):
        assert _format_js_args({}, {}) == ""

    def test_single_string(self):
        params = {"name": {"type": "string"}}
        kwargs = {"name": "test"}
        assert _format_js_args(params, kwargs) == '"test"'

    def test_multiple_args(self):
        params = {"addr": {"type": "string"}, "count": {"type": "integer"}}
        kwargs = {"addr": "@rsp", "count": 10}
        assert _format_js_args(params, kwargs) == '"@rsp", 10'

    def test_missing_optional_arg(self):
        params = {"addr": {"type": "string"}, "count": {"type": "integer"}}
        kwargs = {"addr": "@rsp"}
        # Only the provided arg appears
        assert _format_js_args(params, kwargs) == '"@rsp"'

    def test_no_kwargs(self):
        params = {"addr": {"type": "string"}}
        assert _format_js_args(params, {}) == ""


# ---------------------------------------------------------------------------
# discover_js_extensions
# ---------------------------------------------------------------------------


class TestDiscoverJsExtensions:
    def test_returns_empty_when_no_jsprovider(self):
        def run_cmd(cmd):
            return "NatVis (NatVis Visualizer)"

        result = discover_js_extensions(run_cmd)
        assert result == []

    def test_returns_empty_when_command_raises(self):
        def run_cmd(cmd):
            raise Exception("No debugger")

        result = discover_js_extensions(run_cmd)
        assert result == []

    def test_returns_empty_when_no_scripts_found(self):
        """JsProvider present but no scripts on disk."""
        def run_cmd(cmd):
            return "JavaScript (JsProvider)"

        result = discover_js_extensions(run_cmd, config_paths="/nonexistent/path")
        assert result == []

    def test_finds_extension_in_config_path(self):
        """When a script file exists at a configured path, it is discovered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create lldext.js at a path matching the registry
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("// mock lldext")

            def run_cmd(cmd):
                return "JavaScript (JsProvider)"

            result = discover_js_extensions(run_cmd, config_paths=tmpdir)
            names = [ext["name"] for ext in result]
            assert "lldext" in names
            # Verify the resolved path is correct
            lldext = [ext for ext in result if ext["name"] == "lldext"][0]
            assert lldext["script_path"] == script_path


# ---------------------------------------------------------------------------
# load_js_extensions
# ---------------------------------------------------------------------------


class TestLoadJsExtensions:
    def test_successful_load(self):
        def run_cmd(cmd):
            return "JavaScript script successfully loaded from ..."

        extensions = [
            {"name": "test_ext", "script_path": "C:\\test.js", "namespace": "@$scriptContents", "tools": []},
        ]
        results = load_js_extensions(run_cmd, extensions)
        assert results["test_ext"] is True

    def test_failed_load_error_in_output(self):
        def run_cmd(cmd):
            return "Error: script load failed"

        extensions = [
            {"name": "test_ext", "script_path": "C:\\test.js", "namespace": "@$scriptContents", "tools": []},
        ]
        results = load_js_extensions(run_cmd, extensions)
        assert results["test_ext"] is False

    def test_failed_load_exception(self):
        def run_cmd(cmd):
            raise Exception("pykd error")

        extensions = [
            {"name": "test_ext", "script_path": "C:\\test.js", "namespace": "@$scriptContents", "tools": []},
        ]
        results = load_js_extensions(run_cmd, extensions)
        assert results["test_ext"] is False

    def test_multiple_extensions(self):
        call_count = {"n": 0}

        def run_cmd(cmd):
            call_count["n"] += 1
            if "bad" in cmd:
                return "Error loading script"
            return "Loaded successfully"

        extensions = [
            {"name": "good", "script_path": "C:\\good.js", "namespace": "@$scriptContents", "tools": []},
            {"name": "bad", "script_path": "C:\\bad.js", "namespace": "@$scriptContents", "tools": []},
        ]
        results = load_js_extensions(run_cmd, extensions)
        assert results["good"] is True
        assert results["bad"] is False


# ---------------------------------------------------------------------------
# make_js_tool_function
# ---------------------------------------------------------------------------


class TestMakeJsToolFunction:
    def test_produces_valid_json_schema_docstring(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="js_test_analyze",
            description="Test analysis function",
            params={},
        )
        schema = json.loads(func.__doc__)
        assert schema["name"] == "js_test_analyze"
        assert schema["description"] == "Test analysis function"
        assert schema["parameters"]["type"] == "object"

    def test_no_params_produces_empty_properties(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="js_test_analyze",
            description="Test",
            params={},
        )
        schema = json.loads(func.__doc__)
        assert schema["parameters"]["properties"] == {}

    def test_with_params_in_schema(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="telescope",
            tool_name="js_test_telescope",
            description="Telescope memory",
            params={"address": {"type": "string", "description": "Memory address"}},
            required=["address"],
        )
        schema = json.loads(func.__doc__)
        assert "address" in schema["parameters"]["properties"]
        assert schema["parameters"]["required"] == ["address"]

    def test_function_name_set(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="js_test_analyze",
            description="Test",
            params={},
        )
        assert func.__name__ == "js_test_analyze"

    def test_calls_run_one_command_with_correct_dx(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="js_test_analyze",
            description="Test",
            params={},
        )

        # Create a mock self with _run_one_command
        mock_self = MagicMock()
        mock_self._run_one_command.return_value = "analysis output"

        cmd, output = func(mock_self)
        mock_self._run_one_command.assert_called_once_with(
            "dx @$scriptContents.analyze()"
        )
        assert cmd == "dx @$scriptContents.analyze()"
        assert output == "analysis output"

    def test_calls_with_string_argument(self):
        func = make_js_tool_function(
            ext_name="test",
            namespace="@$scriptContents",
            js_func="telescope",
            tool_name="js_test_telescope",
            description="Telescope",
            params={"address": {"type": "string"}},
            required=["address"],
        )

        mock_self = MagicMock()
        mock_self._run_one_command.return_value = "telescope output"

        cmd, output = func(mock_self, address="@rsp")
        mock_self._run_one_command.assert_called_once_with(
            'dx @$scriptContents.telescope("@rsp")'
        )

    def test_handles_exception(self):
        func = make_js_tool_function(
            ext_name="myext",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="js_myext_analyze",
            description="Test",
            params={},
        )

        mock_self = MagicMock()
        mock_self._run_one_command.side_effect = Exception("dx failed")

        cmd, output = func(mock_self)
        assert "Error calling myext.analyze" in output


# ---------------------------------------------------------------------------
# make_tool_functions
# ---------------------------------------------------------------------------


class TestMakeToolFunctions:
    def test_generates_tools_for_loaded_extensions(self):
        extensions = [
            {
                "name": "ext1",
                "script_path": "C:\\ext1.js",
                "namespace": "@$scriptContents",
                "tools": [
                    {
                        "js_func": "func1",
                        "tool_name": "js_ext1_func1",
                        "description": "Function 1",
                        "parameters": {},
                    },
                    {
                        "js_func": "func2",
                        "tool_name": "js_ext1_func2",
                        "description": "Function 2",
                        "parameters": {"x": {"type": "integer"}},
                    },
                ],
            },
        ]
        tools = make_tool_functions(extensions)
        assert len(tools) == 2
        assert tools[0].__name__ == "js_ext1_func1"
        assert tools[1].__name__ == "js_ext1_func2"

    def test_empty_extensions(self):
        assert make_tool_functions([]) == []
