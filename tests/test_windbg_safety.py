import pytest

from chatdbg.native_util.windbg_safety import windbg_command_is_safe


class TestSafeCommands:
    """Commands that should always be allowed."""

    @pytest.mark.parametrize("cmd", [
        "k", "kb", "kp", "kn", "kv", "kd", "kc",
    ])
    def test_stack_commands(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "k 20", "kb 10", "kp 5",
    ])
    def test_stack_commands_with_args(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    def test_frame(self):
        assert windbg_command_is_safe(".frame") is True
        assert windbg_command_is_safe(".frame 3") is True

    @pytest.mark.parametrize("cmd", ["lm", "x", "ln"])
    def test_modules_symbols(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", ["u", "uf", "ub"])
    def test_disassembly(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "dv", "dv /t", "dt",
    ])
    def test_variables_types(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "db", "dw", "dd", "dq", "dp", "da", "du",
    ])
    def test_memory_display(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "!analyze", "!analyze -v", ".ecxr", ".exr", ".lastevent",
    ])
    def test_analysis(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "!clrstack", "!dumpobj", "!dumpstackobjects",
        "!dumpheap", "!dumpmt", "!name2ee",
        "!eestack", "!threads", "!gcroot", "!pe",
    ])
    def test_sos_commands(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", ["!tt", "!positions"])
    def test_ttd(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "version", "vertarget", "!peb", "!teb",
    ])
    def test_info(self, cmd):
        assert windbg_command_is_safe(cmd) is True


class TestCaseInsensitivity:
    """WinDbg commands are case-insensitive."""

    def test_mixed_case_extension(self):
        assert windbg_command_is_safe("!DumpObj") is True
        assert windbg_command_is_safe("!CLRSTACK") is True
        assert windbg_command_is_safe("!Analyze -v") is True

    def test_uppercase_builtin(self):
        assert windbg_command_is_safe("K") is True
        assert windbg_command_is_safe("LM") is True
        assert windbg_command_is_safe("DV") is True


class TestConditionalCommands:
    """Commands that are safe only in certain forms."""

    # ? (evaluate) — safe with simple expressions
    @pytest.mark.parametrize("cmd", [
        "? @eax",
        "? @eax + 4",
        "? poi(@esp)",
        "? @rsp - @rbp",
        "? 0x1000 + 0x20",
        "? $teb",
    ])
    def test_safe_evaluate_expressions(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        '? system("cmd")',
        "? `malicious`",
    ])
    def test_blocked_evaluate_expressions(self, cmd):
        assert windbg_command_is_safe(cmd) is False

    # r (registers) — safe for reads, blocked for writes
    @pytest.mark.parametrize("cmd", [
        "r",
        "r rax",
        "r rip",
        "r eax, ebx",
    ])
    def test_safe_register_reads(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        "r rax=0",
        "r rip=0x41414141",
        "r eax=0xdeadbeef",
    ])
    def test_blocked_register_writes(self, cmd):
        assert windbg_command_is_safe(cmd) is False

    # dx (expression evaluator) — safe for property access, blocked for method calls
    @pytest.mark.parametrize("cmd", [
        "dx @$curprocess",
        "dx @$curprocess.Name",
        "dx @$curthread.Id",
    ])
    def test_safe_dx_expressions(self, cmd):
        assert windbg_command_is_safe(cmd) is True

    @pytest.mark.parametrize("cmd", [
        'dx Debugger.Sessions.First().Processes.First().Terminate()',
        "dx @$curprocess.Threads.First()",
        "dx @$curprocess.Threads.Count()",
    ])
    def test_blocked_dx_method_calls(self, cmd):
        assert windbg_command_is_safe(cmd) is False


class TestBlockedCommands:
    """Commands that must be rejected."""

    @pytest.mark.parametrize("cmd", [
        "g", "p", "t",
    ])
    def test_execution_commands(self, cmd):
        assert windbg_command_is_safe(cmd) is False

    @pytest.mark.parametrize("cmd", [
        "ed", "ew", "eb",
    ])
    def test_memory_edit_commands(self, cmd):
        assert windbg_command_is_safe(cmd) is False

    @pytest.mark.parametrize("cmd", [
        ".shell", ".kill", ".detach", ".restart",
    ])
    def test_dangerous_meta_commands(self, cmd):
        assert windbg_command_is_safe(cmd) is False

    def test_unlisted_commands(self):
        assert windbg_command_is_safe("bp 0x401000") is False
        assert windbg_command_is_safe(".reload") is False


class TestScriptCommands:
    """Script provider commands: read-only queries allowed, loading blocked."""

    def test_scriptproviders_allowed(self):
        assert windbg_command_is_safe(".scriptproviders") is True

    def test_scriptlist_allowed(self):
        assert windbg_command_is_safe(".scriptlist") is True

    def test_scriptload_blocked(self):
        assert windbg_command_is_safe('.scriptload "C:\\ext.js"') is False

    def test_scriptrun_blocked(self):
        assert windbg_command_is_safe('.scriptrun "C:\\ext.js"') is False

    def test_dx_scriptcontents_blocked(self):
        """LLM must use dedicated tools, not raw dx calls to script functions."""
        assert windbg_command_is_safe("dx @$scriptContents.analyze()") is False

    def test_dx_scriptcontents_property_blocked(self):
        """Even property-looking calls with parentheses are blocked."""
        assert windbg_command_is_safe("dx @$scriptContents.func()") is False


class TestEdgeCases:
    """Edge cases and whitespace handling."""

    def test_empty_string(self):
        assert windbg_command_is_safe("") is False

    def test_whitespace_only(self):
        assert windbg_command_is_safe("   ") is False

    def test_leading_trailing_whitespace(self):
        assert windbg_command_is_safe("  k  ") is True
        assert windbg_command_is_safe("\t!analyze -v\t") is True
