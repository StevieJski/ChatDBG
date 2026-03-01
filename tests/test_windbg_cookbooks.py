"""
Unit tests for conditional cookbook loading in WinDbgDialog.

Tests that the JS and .NET cookbooks are correctly appended to the system
prompt based on runtime detection of JsProvider and CLR.
"""

import os
import sys
import pytest

# Insert tests/ onto sys.path so we can import mock_pykd
sys.path.insert(0, os.path.dirname(__file__))

from mock_pykd import MockPyKD

INSTRUCTIONS_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "src",
    "chatdbg",
    "util",
    "instructions",
)


# ---------------------------------------------------------------------------
# Cookbook file existence tests
# ---------------------------------------------------------------------------


class TestCookbookFilesExist:
    def test_js_cookbook_exists_and_nonempty(self):
        path = os.path.join(INSTRUCTIONS_DIR, "windbg_js_cookbook.txt")
        assert os.path.exists(path), "windbg_js_cookbook.txt should exist"
        assert os.path.getsize(path) > 0, "windbg_js_cookbook.txt should be non-empty"

    def test_dotnet_cookbook_exists_and_nonempty(self):
        path = os.path.join(INSTRUCTIONS_DIR, "windbg_dotnet_cookbook.txt")
        assert os.path.exists(path), "windbg_dotnet_cookbook.txt should exist"
        assert os.path.getsize(path) > 0, "windbg_dotnet_cookbook.txt should be non-empty"


# ---------------------------------------------------------------------------
# JS cookbook content tests
# ---------------------------------------------------------------------------


class TestJsCookbookContent:
    def test_contains_key_patterns(self):
        path = os.path.join(INSTRUCTIONS_DIR, "windbg_js_cookbook.txt")
        with open(path, "r") as f:
            content = f.read()
        assert "ExecuteCommand" in content
        assert "for...of" in content
        assert "parseInt64" in content
        assert "readMemoryValues" in content


# ---------------------------------------------------------------------------
# .NET cookbook content tests
# ---------------------------------------------------------------------------


class TestDotnetCookbookContent:
    def test_contains_key_patterns(self):
        path = os.path.join(INSTRUCTIONS_DIR, "windbg_dotnet_cookbook.txt")
        with open(path, "r") as f:
            content = f.read()
        assert "print_exception" in content
        assert "managed_stack" in content
        assert "DumpAsync" in content
        assert "SyncBlk" in content
        assert "FinalizeQueue" in content


# ---------------------------------------------------------------------------
# Conditional inclusion tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cleanup_modules():
    """Remove cached chatdbg modules after each test."""
    yield
    sys.modules.pop("pykd", None)
    for mod_name in list(sys.modules.keys()):
        if "chatdbg_windbg" in mod_name or "chatdbg.chatdbg_windbg" in mod_name:
            del sys.modules[mod_name]


def _install_mock(scenario):
    mock = MockPyKD(scenario=scenario)
    sys.modules["pykd"] = mock
    # Force reimport
    for mod_name in list(sys.modules.keys()):
        if "chatdbg_windbg" in mod_name or "chatdbg.chatdbg_windbg" in mod_name:
            del sys.modules[mod_name]
    return mock


class TestJsCookbookConditionalInclusion:
    def test_included_when_jsprovider_detected(self):
        _install_mock("js_scripting")
        from chatdbg.chatdbg_windbg import WinDbgDialog

        dialog = WinDbgDialog("(test) ")
        instructions = dialog.initial_prompt_instructions()
        assert "ExecuteCommand" in instructions
        assert "for...of" in instructions
        assert "parseInt64" in instructions

    def test_not_included_in_native_crash(self):
        _install_mock("native_crash")
        from chatdbg.chatdbg_windbg import WinDbgDialog

        dialog = WinDbgDialog("(test) ")
        instructions = dialog.initial_prompt_instructions()
        assert "readMemoryValues" not in instructions
        # The base windbg.txt mentions ExecuteCommand, so check for
        # JS-cookbook-specific content instead
        assert "for...of" not in instructions


class TestDotnetCookbookConditionalInclusion:
    def test_included_when_clr_detected(self):
        _install_mock("dotnet_crash")
        from chatdbg.chatdbg_windbg import WinDbgDialog

        dialog = WinDbgDialog("(test) ")
        instructions = dialog.initial_prompt_instructions()
        assert "Recommended Investigation Workflow" in instructions
        assert "DumpAsync" in instructions
        assert "SyncBlk" in instructions

    def test_not_included_in_native_crash(self):
        _install_mock("native_crash")
        from chatdbg.chatdbg_windbg import WinDbgDialog

        dialog = WinDbgDialog("(test) ")
        instructions = dialog.initial_prompt_instructions()
        assert "Recommended Investigation Workflow" not in instructions
        assert "DumpAsync" not in instructions


class TestCombinedScenario:
    def test_both_cookbooks_included(self):
        _install_mock("dotnet_js")
        from chatdbg.chatdbg_windbg import WinDbgDialog

        dialog = WinDbgDialog("(test) ")
        instructions = dialog.initial_prompt_instructions()
        # JS cookbook markers
        assert "for...of" in instructions
        assert "readMemoryValues" in instructions
        # .NET cookbook markers
        assert "Recommended Investigation Workflow" in instructions
        assert "DumpAsync" in instructions
