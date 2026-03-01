"""
Unit tests for WinDbg JavaScript scripting (run_js tool).
"""

import json
import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from chatdbg.windbg_js_scripting import (
    _check_js_safety,
    _JS_TEMPLATE,
    llm_run_js,
    JS_SCRIPTING_TOOLS,
)


# ---------------------------------------------------------------------------
# Safety check tests
# ---------------------------------------------------------------------------


class TestCheckJsSafety:
    """_check_js_safety blocks dangerous patterns and allows safe code."""

    @pytest.mark.parametrize("code,expected_keyword", [
        # Memory writes
        ('host.namespace.Debugger.Utility.Control.ExecuteCommand("eb 0x1234 90")', "memory write"),
        ('ExecuteCommand("ew 0x1000 0x4141")', "memory write"),
        ('ExecuteCommand("ed 0x1000 0xdeadbeef")', "memory write"),
        # Execution resume
        ('ExecuteCommand("g")', "execution resume"),
        ('ExecuteCommand("p")', "execution resume"),
        ('ExecuteCommand("t")', "execution resume"),
        # Register writes
        ('ExecuteCommand("r rax=0x41414141")', "register write"),
        ('ExecuteCommand("r rip=0")', "register write"),
        # Kill / detach
        ('ExecuteCommand(".kill")', "kill target"),
        ('ExecuteCommand(".detach")', "detach target"),
        # Restart
        ('ExecuteCommand(".restart")', "restart target"),
        # Breakpoints
        ('ExecuteCommand("bp 0x401000")', "set breakpoint"),
    ])
    def test_blocks_dangerous_patterns(self, code, expected_keyword):
        result = _check_js_safety(code)
        assert result is not None, f"Expected block for: {code}"
        assert expected_keyword in result.lower(), f"Expected '{expected_keyword}' in '{result}'"

    @pytest.mark.parametrize("code", [
        # Read-only analysis code
        'var frames = host.currentThread.Stack.Frames;',
        'var proc = host.currentProcess;',
        'host.diagnostics.debugLog("hello");',
        'var result = host.namespace.Debugger.Utility.Control.ExecuteCommand("k");',
        'ExecuteCommand("!analyze -v")',
        'ExecuteCommand("dv /t")',
        'ExecuteCommand("db 0x1000")',
        'ExecuteCommand("r")',
        'ExecuteCommand("lm")',
        'var x = host.parseInt64("0x1000");',
        'return "done";',
    ])
    def test_allows_safe_code(self, code):
        result = _check_js_safety(code)
        assert result is None, f"Unexpected block for: {code} — got: {result}"


# ---------------------------------------------------------------------------
# JS template tests
# ---------------------------------------------------------------------------


class TestJsTemplate:
    def test_template_wraps_code(self):
        code = "    var x = 1;\n    return x;"
        result = _JS_TEMPLATE.format(code=code)
        assert '"use strict";' in result
        assert "function run()" in result
        assert "var x = 1;" in result
        assert "return x;" in result


# ---------------------------------------------------------------------------
# Tool schema tests
# ---------------------------------------------------------------------------


class TestToolSchema:
    def test_valid_json_schema(self):
        schema = json.loads(llm_run_js.__doc__)
        assert schema["name"] == "run_js"
        assert schema["parameters"]["type"] == "object"
        assert "code" in schema["parameters"]["properties"]
        assert "code" in schema["parameters"]["required"]

    def test_code_parameter_is_string(self):
        schema = json.loads(llm_run_js.__doc__)
        assert schema["parameters"]["properties"]["code"]["type"] == "string"

    def test_export_list(self):
        assert llm_run_js in JS_SCRIPTING_TOOLS
        assert len(JS_SCRIPTING_TOOLS) == 1


# ---------------------------------------------------------------------------
# Execution tests
# ---------------------------------------------------------------------------


class TestLlmRunJs:
    """Test the llm_run_js function with mocked self and config."""

    def _make_mock_self(self, responses=None):
        mock_self = MagicMock()
        if responses is None:
            responses = {}

        def run_cmd(cmd):
            if cmd in responses:
                val = responses[cmd]
                if isinstance(val, Exception):
                    raise val
                return val
            if cmd.startswith(".scriptload"):
                return "JavaScript script successfully loaded."
            if cmd.startswith("dx @$scriptContents.run()"):
                return "@$scriptContents.run()\n    result: 42\n"
            if cmd.startswith(".scriptunload"):
                return ""
            return ""

        mock_self._run_one_command = MagicMock(side_effect=run_cmd)
        return mock_self

    @patch("chatdbg.util.config.chatdbg_config")
    def test_successful_execution(self, mock_config):
        mock_config.unsafe = False
        mock_self = self._make_mock_self()

        cmd, output = llm_run_js(mock_self, code='var x = 1;\nreturn x;')

        assert cmd == "run_js"
        assert "42" in output

        # Verify all three commands were called: scriptload, dx run(), scriptunload
        calls = [str(c) for c in mock_self._run_one_command.call_args_list]
        assert any(".scriptload" in c for c in calls)
        assert any("dx @$scriptContents.run()" in c for c in calls)
        assert any(".scriptunload" in c for c in calls)

    @patch("chatdbg.util.config.chatdbg_config")
    def test_safety_blocks_dangerous_code(self, mock_config):
        mock_config.unsafe = False
        mock_self = self._make_mock_self()

        cmd, output = llm_run_js(mock_self, code='ExecuteCommand("eb 0x1000 90")')

        assert "blocked" in cmd.lower()
        assert "safety check" in output.lower()
        # Should NOT call any debugger commands
        mock_self._run_one_command.assert_not_called()

    @patch("chatdbg.util.config.chatdbg_config")
    def test_unsafe_bypasses_safety(self, mock_config):
        mock_config.unsafe = True
        mock_self = self._make_mock_self()

        cmd, output = llm_run_js(mock_self, code='ExecuteCommand("eb 0x1000 90")')

        assert cmd == "run_js"
        # Should proceed to execution
        assert mock_self._run_one_command.call_count >= 2  # scriptload + dx run

    @patch("chatdbg.util.config.chatdbg_config")
    def test_script_load_failure(self, mock_config):
        mock_config.unsafe = False
        mock_self = self._make_mock_self()
        mock_self._run_one_command = MagicMock(
            return_value="Error: unable to load script"
        )

        cmd, output = llm_run_js(mock_self, code='return 1;')

        assert "failed" in output.lower() or "error" in output.lower()

    @patch("chatdbg.util.config.chatdbg_config")
    def test_execution_error(self, mock_config):
        mock_config.unsafe = False

        call_count = {"n": 0}

        def run_cmd(cmd):
            call_count["n"] += 1
            if cmd.startswith(".scriptload"):
                return "JavaScript script successfully loaded."
            if "dx @$scriptContents.run()" in cmd:
                raise Exception("syntax error in script")
            if cmd.startswith(".scriptunload"):
                return ""
            return ""

        mock_self = MagicMock()
        mock_self._run_one_command = MagicMock(side_effect=run_cmd)

        cmd, output = llm_run_js(mock_self, code='bad syntax here;')

        assert cmd == "run_js"
        assert "error" in output.lower()

    @patch("chatdbg.util.config.chatdbg_config")
    def test_temp_file_cleanup(self, mock_config):
        """Verify temp file is deleted even on success."""
        mock_config.unsafe = False
        mock_self = self._make_mock_self()

        created_files = []
        original_mkstemp = tempfile.mkstemp

        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_files.append(path)
            return fd, path

        with patch("chatdbg.windbg_js_scripting.tempfile.mkstemp", side_effect=tracking_mkstemp):
            llm_run_js(mock_self, code='return 1;')

        assert len(created_files) == 1
        assert not os.path.exists(created_files[0]), "Temp file should be deleted"

    @patch("chatdbg.util.config.chatdbg_config")
    def test_temp_file_cleanup_on_error(self, mock_config):
        """Verify temp file is deleted even when execution fails."""
        mock_config.unsafe = False

        def run_cmd(cmd):
            if cmd.startswith(".scriptload"):
                return "JavaScript script successfully loaded."
            if "dx @$scriptContents.run()" in cmd:
                raise Exception("crash")
            return ""

        mock_self = MagicMock()
        mock_self._run_one_command = MagicMock(side_effect=run_cmd)

        created_files = []
        original_mkstemp = tempfile.mkstemp

        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_files.append(path)
            return fd, path

        with patch("chatdbg.windbg_js_scripting.tempfile.mkstemp", side_effect=tracking_mkstemp):
            llm_run_js(mock_self, code='crash;')

        assert len(created_files) == 1
        assert not os.path.exists(created_files[0]), "Temp file should be deleted on error"


# ---------------------------------------------------------------------------
# Integration test with mock pykd
# ---------------------------------------------------------------------------


class TestIntegrationWithMockPykd:
    """Test that WinDbgDialog registers run_js when JsProvider is available."""

    @pytest.fixture(autouse=True)
    def install_mock_pykd(self):
        sys.path.insert(0, os.path.dirname(__file__))
        from mock_pykd import MockPyKD
        mock = MockPyKD(scenario="js_scripting")
        sys.modules["pykd"] = mock
        yield mock
        sys.modules.pop("pykd", None)
        for mod_name in list(sys.modules.keys()):
            if "chatdbg_windbg" in mod_name:
                del sys.modules[mod_name]

    def test_jsprovider_detected(self, install_mock_pykd):
        from chatdbg.chatdbg_windbg import WinDbgDialog
        dialog = WinDbgDialog("(test) ")
        assert dialog._detect_jsprovider() is True

    def test_run_js_registered(self, install_mock_pykd):
        from chatdbg.chatdbg_windbg import WinDbgDialog
        dialog = WinDbgDialog("(test) ")
        functions = dialog._supported_functions()
        names = [f.__func__.__name__ if hasattr(f, '__func__') else f.__name__ for f in functions]
        assert "llm_run_js" in names

    def test_jsprovider_not_detected_in_native(self):
        """In native_crash scenario (no JsProvider), run_js should not be registered."""
        sys.path.insert(0, os.path.dirname(__file__))
        from mock_pykd import MockPyKD
        mock = MockPyKD(scenario="native_crash")
        sys.modules["pykd"] = mock
        # Clear cached module
        for mod_name in list(sys.modules.keys()):
            if "chatdbg_windbg" in mod_name:
                del sys.modules[mod_name]

        from chatdbg.chatdbg_windbg import WinDbgDialog
        dialog = WinDbgDialog("(test) ")
        assert dialog._detect_jsprovider() is False
        functions = dialog._supported_functions()
        names = [f.__func__.__name__ if hasattr(f, '__func__') else f.__name__ for f in functions]
        assert "llm_run_js" not in names
