"""
Integration tests for WinDbgDialog using mock_pykd.

These tests exercise the full WinDbg backend without requiring WinDbg
or PyKD to be installed.
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Insert tests/ onto sys.path so we can import mock_pykd
sys.path.insert(0, os.path.dirname(__file__))

from mock_pykd import MockPyKD, EXECUTION_STATUS_BREAK


@pytest.fixture(autouse=True)
def install_mock_pykd():
    """Install mock pykd before each test, remove after."""
    mock = MockPyKD(scenario="native_crash")
    sys.modules["pykd"] = mock
    yield mock
    sys.modules.pop("pykd", None)
    # Force reimport of chatdbg_windbg to pick up fresh mock
    for mod_name in list(sys.modules.keys()):
        if "chatdbg_windbg" in mod_name:
            del sys.modules[mod_name]


@pytest.fixture
def dialog(install_mock_pykd):
    """Create a WinDbgDialog with mock pykd installed."""
    from chatdbg.chatdbg_windbg import WinDbgDialog
    return WinDbgDialog("(test) ")


class TestRunOneCommand:
    def test_basic_command(self, dialog, install_mock_pykd):
        result = dialog._run_one_command("k 20")
        assert "crash_sample!main" in result

    def test_command_error_returns_string(self, dialog, install_mock_pykd):
        # When pykd.dbgCommand raises an exception, _run_one_command returns error string
        install_mock_pykd.set_response("bad_cmd", Exception("test error"))
        # The mock returns "" for unknown commands, so test the exception path
        original_dbgCommand = install_mock_pykd.dbgCommand
        def raising_dbgCommand(cmd):
            if cmd == "bad_cmd":
                raise Exception("test error")
            return original_dbgCommand(cmd)
        install_mock_pykd.dbgCommand = raising_dbgCommand
        result = dialog._run_one_command("bad_cmd")
        assert isinstance(result, str)
        assert "test error" in result


class TestMessageIsBadCommandError:
    def test_unknown_command(self, dialog):
        assert dialog._message_is_a_bad_command_error("Unknown command 'foo'")

    def test_no_export(self, dialog):
        assert dialog._message_is_a_bad_command_error("No export bar found")

    def test_couldnt_resolve(self, dialog):
        assert dialog._message_is_a_bad_command_error("Couldn't resolve error at 'baz'")

    def test_not_found(self, dialog):
        assert dialog._message_is_a_bad_command_error("Command not found")

    def test_invalid_command(self, dialog):
        assert dialog._message_is_a_bad_command_error("Invalid command syntax")

    def test_valid_output(self, dialog):
        assert not dialog._message_is_a_bad_command_error("rax=0000000000000000")


class TestCheckDebuggerState:
    def test_valid_state(self, dialog, install_mock_pykd):
        # Should not raise
        dialog.check_debugger_state()

    def test_not_in_break_state(self, dialog, install_mock_pykd):
        install_mock_pykd.set_execution_status(0)  # GO state
        from chatdbg.native_util.dbg_dialog import DBGError
        with pytest.raises(DBGError, match="breakpoint"):
            dialog.check_debugger_state()

    def test_empty_stack(self, dialog, install_mock_pykd):
        install_mock_pykd.getStack = lambda: []
        from chatdbg.native_util.dbg_dialog import DBGError
        with pytest.raises(DBGError, match="stack frames"):
            dialog.check_debugger_state()


class TestGetFrameSummaries:
    def test_returns_frames(self, dialog):
        summaries = dialog._get_frame_summaries()
        assert summaries is not None
        assert len(summaries) > 0

    def test_frame_has_name(self, dialog):
        summaries = dialog._get_frame_summaries()
        from chatdbg.native_util.stacks import _FrameSummaryEntry
        frame_entries = [s for s in summaries if isinstance(s, _FrameSummaryEntry)]
        assert len(frame_entries) > 0
        # First frame should be main
        first_frame = str(frame_entries[0])
        assert "crash_sample!main" in first_frame

    def test_max_entries_respected(self, dialog):
        summaries = dialog._get_frame_summaries(max_entries=2)
        assert summaries is not None
        assert len(summaries) <= 3  # 2 entries + possible skipped entry


class TestInitialPromptErrorMessage:
    def test_analyze_output(self, dialog):
        result = dialog._initial_prompt_error_message()
        assert result is not None
        assert "EXCEPTION_CODE" in result or "c0000005" in result.lower()


class TestInitialPromptErrorDetails:
    def test_ecxr_output(self, dialog):
        result = dialog._initial_prompt_error_details()
        assert result is not None
        assert "rax=" in result or "crash_sample" in result


class TestInitialPromptCommandLine:
    def test_peb_parsing(self, dialog):
        result = dialog._initial_prompt_command_line()
        assert result is not None
        assert "crash_sample" in result


class TestPromptStack:
    def test_returns_stack(self, dialog):
        result = dialog._prompt_stack()
        assert result is not None
        assert "crash_sample" in result


class TestLlmDebug:
    def test_safe_command(self, dialog):
        cmd, output = dialog.llm_debug("k")
        assert cmd == "k"
        assert isinstance(output, str)

    def test_blocked_command(self, dialog):
        cmd, output = dialog.llm_debug("g")
        assert cmd == "g"
        assert "not allowed" in output

    def test_unsafe_mode(self, dialog):
        from chatdbg.util.config import chatdbg_config
        original = chatdbg_config.unsafe
        try:
            chatdbg_config.unsafe = True
            cmd, output = dialog.llm_debug("g")
            assert cmd == "g"
            assert "not allowed" not in output
        finally:
            chatdbg_config.unsafe = original


class TestSupportedFunctions:
    def test_basic_functions(self, dialog):
        functions = dialog._supported_functions()
        names = [f.__doc__ for f in functions if f.__doc__]
        # Should have at least debug and get_code_surrounding
        assert len(functions) >= 2

    def test_no_ttd_by_default(self, dialog):
        functions = dialog._supported_functions()
        func_docs = " ".join(f.__doc__ or "" for f in functions)
        assert "ttd" not in func_docs.lower()

    def test_no_dotnet_by_default(self, dialog):
        functions = dialog._supported_functions()
        func_docs = " ".join(f.__doc__ or "" for f in functions)
        assert "managed_stack" not in func_docs


class TestDotnetDetection:
    def test_detect_coreclr(self, install_mock_pykd, dialog):
        install_mock_pykd._fixtures["lm"] = (
            "start end module\n"
            "00007ff8`10000000 00007ff8`10500000 coreclr (deferred)\n"
        )
        dialog._is_dotnet = None  # Reset cache
        assert dialog._detect_dotnet() is True

    def test_no_clr(self, dialog):
        assert dialog._detect_dotnet() is False


class TestTtdDetection:
    def test_detect_ttd(self, install_mock_pykd, dialog):
        install_mock_pykd.set_response(
            "dx @$curprocess.TTD",
            "@$curprocess.TTD\n    Lifetime : [0:0, 50:0]\n"
        )
        dialog._is_ttd = None  # Reset cache
        assert dialog._detect_ttd() is True

    def test_no_ttd(self, dialog):
        assert dialog._detect_ttd() is False


class TestSupportedFunctionsWithTtd:
    def test_ttd_tools_added(self, install_mock_pykd):
        install_mock_pykd.set_response(
            "dx @$curprocess.TTD",
            "@$curprocess.TTD\n    Lifetime : [0:0, 50:0]\n"
        )
        from chatdbg.chatdbg_windbg import WinDbgDialog
        dialog = WinDbgDialog("(test) ")
        dialog._is_ttd = None
        functions = dialog._supported_functions()
        func_docs = " ".join(f.__doc__ or "" for f in functions)
        assert "ttd_step_back" in func_docs


class TestSupportedFunctionsWithDotnet:
    def test_dotnet_tools_added(self, install_mock_pykd):
        install_mock_pykd._fixtures["lm"] = (
            "start end module\n"
            "00007ff8`10000000 00007ff8`10500000 coreclr (deferred)\n"
        )
        from chatdbg.chatdbg_windbg import WinDbgDialog
        dialog = WinDbgDialog("(test) ")
        dialog._is_dotnet = None
        functions = dialog._supported_functions()
        func_docs = " ".join(f.__doc__ or "" for f in functions)
        assert "managed_stack" in func_docs
        assert "print_exception" in func_docs


class TestJsExtensionDiscovery:
    """Test JS extension discovery via the dialog."""

    def test_no_jsprovider_no_tools(self, dialog):
        """Without JsProvider, no JS extension tools are registered."""
        assert dialog._js_extension_tools == []

    def test_no_jsprovider_supported_functions_unchanged(self, dialog):
        """Supported functions should not include JS tools when no provider."""
        functions = dialog._supported_functions()
        func_docs = " ".join(f.__doc__ or "" for f in functions)
        assert "js_lldext" not in func_docs

    def test_jsprovider_available_with_scripts(self, install_mock_pykd):
        """When JsProvider is present and scripts exist, tools are registered."""
        import tempfile
        import os

        # Switch to js_extensions scenario
        install_mock_pykd.scenario = "js_extensions"
        install_mock_pykd._fixtures[".scriptproviders"] = (
            "Available Script Providers:\n"
            "    NatVis (NatVis Visualizer)\n"
            "    JavaScript (JsProvider)\n"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a script file that matches the lldext registry entry
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("// mock lldext")

            from chatdbg.util.config import chatdbg_config
            original_js = chatdbg_config.js_extensions
            try:
                chatdbg_config.js_extensions = tmpdir

                # Force reimport to pick up fresh mock state
                for mod_name in list(sys.modules.keys()):
                    if "chatdbg_windbg" in mod_name:
                        del sys.modules[mod_name]

                from chatdbg.chatdbg_windbg import WinDbgDialog
                dialog = WinDbgDialog("(test) ")

                assert len(dialog._js_extension_tools) > 0
                tool_names = [t.__name__ for t in dialog._js_extension_tools]
                assert "js_lldext_analyze" in tool_names
            finally:
                chatdbg_config.js_extensions = original_js

    def test_js_tools_appear_in_supported_functions(self, install_mock_pykd):
        """JS extension tools should appear in _supported_functions()."""
        import tempfile
        import os

        install_mock_pykd.scenario = "js_extensions"
        install_mock_pykd._fixtures[".scriptproviders"] = (
            "Available Script Providers:\n"
            "    JavaScript (JsProvider)\n"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("// mock")

            from chatdbg.util.config import chatdbg_config
            original_js = chatdbg_config.js_extensions
            try:
                chatdbg_config.js_extensions = tmpdir

                for mod_name in list(sys.modules.keys()):
                    if "chatdbg_windbg" in mod_name:
                        del sys.modules[mod_name]

                from chatdbg.chatdbg_windbg import WinDbgDialog
                dialog = WinDbgDialog("(test) ")

                functions = dialog._supported_functions()
                func_docs = " ".join(f.__doc__ or "" for f in functions)
                assert "js_lldext_analyze" in func_docs
            finally:
                chatdbg_config.js_extensions = original_js

    def test_graceful_failure_on_load_error(self, install_mock_pykd):
        """If script loading fails, dialog still works without JS tools."""
        import tempfile
        import os

        install_mock_pykd.scenario = "js_extensions"
        install_mock_pykd._fixtures[".scriptproviders"] = (
            "JavaScript (JsProvider)\n"
        )
        # Override scriptload to return error
        original_dbgCommand = install_mock_pykd.dbgCommand
        def error_scriptload(cmd):
            if cmd.startswith(".scriptload"):
                return "Error: unable to load script"
            return original_dbgCommand(cmd)
        install_mock_pykd.dbgCommand = error_scriptload

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("// mock")

            from chatdbg.util.config import chatdbg_config
            original_js = chatdbg_config.js_extensions
            try:
                chatdbg_config.js_extensions = tmpdir

                for mod_name in list(sys.modules.keys()):
                    if "chatdbg_windbg" in mod_name:
                        del sys.modules[mod_name]

                from chatdbg.chatdbg_windbg import WinDbgDialog
                dialog = WinDbgDialog("(test) ")

                # No tools should be loaded since scriptload returned error
                assert dialog._js_extension_tools == []
            finally:
                chatdbg_config.js_extensions = original_js
