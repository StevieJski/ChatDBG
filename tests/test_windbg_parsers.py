"""
Tests for the WinDbg TTD and .NET/SOS tool functions.

Each tool wraps a call to self._run_one_command(), so we mock that method
on a fake self object and verify the (command_repr, output) tuples.
"""

import json
from unittest.mock import MagicMock

import pytest

from chatdbg.windbg_tools import (
    llm_ttd_step_back,
    llm_ttd_travel_to,
    llm_ttd_query_exceptions,
    llm_ttd_query_calls,
    llm_managed_stack,
    llm_inspect_object,
    llm_dump_stack_objects,
    llm_print_exception,
    llm_dump_heap_stat,
    llm_dump_heap_type,
    llm_gc_root,
    llm_managed_threads,
    llm_ee_stack,
    llm_name_to_ee,
    TTD_TOOLS,
    DOTNET_TOOLS,
)


@pytest.fixture
def dialog():
    """A mock dialog object with _run_one_command."""
    mock = MagicMock()
    mock._run_one_command = MagicMock(return_value="<output>")
    return mock


# ---------------------------------------------------------------------------
# Docstring schema validation
# ---------------------------------------------------------------------------

ALL_TOOLS = TTD_TOOLS + DOTNET_TOOLS


@pytest.mark.parametrize("func", ALL_TOOLS, ids=[f.__name__ for f in ALL_TOOLS])
def test_docstring_is_valid_json_schema(func):
    schema = json.loads(func.__doc__)
    assert "name" in schema
    assert "description" in schema
    assert "parameters" in schema


# ---------------------------------------------------------------------------
# TTD tools
# ---------------------------------------------------------------------------


class TestTtdStepBack:
    def test_single_step(self, dialog):
        cmd, out = llm_ttd_step_back(dialog, steps=1)
        assert cmd == "t- (x1)"
        dialog._run_one_command.assert_called_with("t-")
        assert out == "<output>"

    def test_multiple_steps(self, dialog):
        dialog._run_one_command.side_effect = ["step1", "step2", "step3"]
        cmd, out = llm_ttd_step_back(dialog, steps=3)
        assert cmd == "t- (x3)"
        assert dialog._run_one_command.call_count == 3
        # Returns the last output
        assert out == "step3"

    def test_default_steps(self, dialog):
        cmd, out = llm_ttd_step_back(dialog)
        assert cmd == "t- (x1)"
        dialog._run_one_command.assert_called_once_with("t-")

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("pykd failure")
        cmd, out = llm_ttd_step_back(dialog, steps=2)
        assert cmd == "t- (x2)"
        assert "Error stepping back" in out


class TestTtdTravelTo:
    def test_basic_travel(self, dialog):
        cmd, out = llm_ttd_travel_to(dialog, position="35:12")
        assert cmd == "!tt 35:12"
        dialog._run_one_command.assert_called_once_with("!tt 35:12")
        assert out == "<output>"

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("bad position")
        cmd, out = llm_ttd_travel_to(dialog, position="999:0")
        assert cmd == "!tt 999:0"
        assert "Error traveling to position" in out


class TestTtdQueryExceptions:
    CANNED_OUTPUT = """\
@$curprocess.TTD.Events.Where(t => t.Type == "Exception")
    [0x0]            : Module Loaded at position: 2A:0
    [0x1]            : Exception at 35:12
    [0x2]            : Exception at 42:5"""

    def test_basic_query(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_ttd_query_exceptions(dialog)
        assert cmd == 'dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception")'
        assert "Exception at 35:12" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("dx failed")
        cmd, out = llm_ttd_query_exceptions(dialog)
        assert "Error querying exceptions" in out


class TestTtdQueryCalls:
    CANNED_OUTPUT = """\
@$curprocess.TTD.Calls("kernel32!CreateFileW")
    [0x0]            : kernel32!CreateFileW  TimeStart: 10:5  TimeEnd: 10:8  ReturnValue: 0xffffffffffffffff"""

    def test_basic_query(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_ttd_query_calls(dialog, function_name="kernel32!CreateFileW")
        assert cmd == 'dx @$curprocess.TTD.Calls("kernel32!CreateFileW")'
        assert "ReturnValue" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("function not found")
        cmd, out = llm_ttd_query_calls(dialog, function_name="bad!Func")
        assert "Error querying calls" in out


# ---------------------------------------------------------------------------
# .NET / SOS tools
# ---------------------------------------------------------------------------


class TestManagedStack:
    CANNED_OUTPUT = """\
OS Thread Id: 0x1234 (0)
        Child SP               IP Call Site
000000abc123ef00 00007ff812345678 MyApp.Program.Main(System.String[])
    PARAMETERS:
        args (0x000001c4a8032fd0) = 0x000001c4a8032fd0
    LOCALS:
        0x000000abc123eef0 = 0x000001c4a8033010"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_managed_stack(dialog)
        assert cmd == "!CLRStack -a"
        dialog._run_one_command.assert_called_once_with("!CLRStack -a")
        assert "MyApp.Program.Main" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("SOS not loaded")
        cmd, out = llm_managed_stack(dialog)
        assert "Error getting managed stack" in out


class TestInspectObject:
    CANNED_OUTPUT = """\
Name:        System.String
MethodTable: 00007ff81234abcd
EEClass:     00007ff81234ef01
Size:        72(0x48) bytes
File:        C:\\Windows\\Microsoft.NET\\...\\System.Private.CoreLib.dll
String:      Hello, World!
Fields:
      MT    Field   Offset                 Type VT     Attr    Value Name
00007ff8 4000001        8         System.Int32  1 instance       13 _stringLength
00007ff8 4000002        c          System.Char  1 instance       48 _firstChar"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_inspect_object(dialog, address="000001c4a8032fd0")
        assert cmd == "!DumpObj 000001c4a8032fd0"
        dialog._run_one_command.assert_called_once_with("!DumpObj 000001c4a8032fd0")
        assert "System.String" in out
        assert "_stringLength" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("invalid address")
        cmd, out = llm_inspect_object(dialog, address="badaddr")
        assert "Error inspecting object" in out


class TestDumpStackObjects:
    CANNED_OUTPUT = """\
OS Thread Id: 0x1234 (0)
RSP/REG          Object           Name
000000abc123ef00 000001c4a8032fd0 System.String
000000abc123ef08 000001c4a8033010 System.String[]
000000abc123ef10 000001c4a8033040 MyApp.Config"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_dump_stack_objects(dialog)
        assert cmd == "!DumpStackObjects"
        dialog._run_one_command.assert_called_once_with("!DumpStackObjects")
        assert "MyApp.Config" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("no CLR")
        cmd, out = llm_dump_stack_objects(dialog)
        assert "Error dumping stack objects" in out


class TestPrintException:
    CANNED_OUTPUT = """\
Exception object: 000001c4a8034500
Exception type:   System.NullReferenceException
Message:          Object reference not set to an instance of an object.
InnerException:   000001c4a8034600, Use "!PrintException 000001c4a8034600" to see more.
StackTrace (generated):
    SP               IP               Function
    000000AB1234EF00 00007FF812345678 DotnetCrash.Program.ProcessData(System.String)

Nested exception -------------------------------------------------------------
Exception object: 000001c4a8034600
Exception type:   System.InvalidOperationException
Message:          Operation is not valid due to the current state of the object."""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_print_exception(dialog)
        assert cmd == "!pe -nested"
        dialog._run_one_command.assert_called_once_with("!pe -nested")
        assert "NullReferenceException" in out
        assert "Nested exception" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("no exception")
        cmd, out = llm_print_exception(dialog)
        assert "Error printing exception" in out


class TestDumpHeapStat:
    CANNED_OUTPUT = """\
Statistics:
              MT    Count    TotalSize Class Name
00007ff81234a004      312        7,488 System.String
00007ff81234a005        2          128 DotnetCrash.Config
Total 402 objects"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_dump_heap_stat(dialog)
        assert cmd == "!DumpHeap -stat"
        dialog._run_one_command.assert_called_once_with("!DumpHeap -stat")
        assert "System.String" in out
        assert "Total 402 objects" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("heap walk failed")
        cmd, out = llm_dump_heap_stat(dialog)
        assert "Error dumping heap stats" in out


class TestDumpHeapType:
    CANNED_OUTPUT = """\
         Address               MT     Size
000001c4a8033040 00007ff81234a005       64
000001c4a8033100 00007ff81234a005       64

Statistics:
              MT    Count    TotalSize Class Name
00007ff81234a005        2          128 DotnetCrash.Config
Total 2 objects"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_dump_heap_type(dialog, typename="DotnetCrash.Config")
        assert cmd == "!DumpHeap -type DotnetCrash.Config"
        dialog._run_one_command.assert_called_once_with("!DumpHeap -type DotnetCrash.Config")
        assert "DotnetCrash.Config" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("type not found")
        cmd, out = llm_dump_heap_type(dialog, typename="Bad.Type")
        assert "Error dumping heap for type" in out


class TestGcRoot:
    CANNED_OUTPUT = """\
Thread 4a2c:
    000000AB1234EF00 00007FF812345678 DotnetCrash.Program.ProcessData(System.String)
        rbp+10: 000000ab1234ef10
            ->  000001C4A8033040 DotnetCrash.Config

Found 2 roots."""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_gc_root(dialog, address="000001C4A8033040")
        assert cmd == "!GCRoot 000001C4A8033040"
        dialog._run_one_command.assert_called_once_with("!GCRoot 000001C4A8033040")
        assert "Found 2 roots" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("invalid address")
        cmd, out = llm_gc_root(dialog, address="badaddr")
        assert "Error tracing GC roots" in out


class TestManagedThreads:
    CANNED_OUTPUT = """\
ThreadCount:      3
UnstartedThread:  0
BackgroundThread: 1
                                                                                                        Lock
       ID OSID ThreadOBJ           State GC Mode     GC Alloc Context                  Domain           Count Apt Exception
   0    1 4a2c 000001C4A0012340  2020020 Preemptive  000001C4A8035010:000001C4A8035FE0 000001c4a0001230 0     Ukn System.NullReferenceException 000001c4a8034500
   3    2 5b3d 000001C4A0012380  2b220b0 Preemptive  0000000000000000:0000000000000000 000001c4a0001230 0     Ukn (Finalizer)"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_managed_threads(dialog)
        assert cmd == "!Threads"
        dialog._run_one_command.assert_called_once_with("!Threads")
        assert "ThreadCount" in out
        assert "Finalizer" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("no CLR")
        cmd, out = llm_managed_threads(dialog)
        assert "Error listing managed threads" in out


class TestEeStack:
    CANNED_OUTPUT = """\
---------------------------------------------
Thread   0
Current frame: ntdll!NtWaitForSingleObject+0x14
Child-SP         RetAddr          Call Site
000000AB1234EF00 00007FF812345678 DotnetCrash.Program.ProcessData(System.String)
000000AB1234EF40 00007FF823456789 DotnetCrash.Program.Main(System.String[])

---------------------------------------------
Thread   3
Current frame: ntdll!NtWaitForSingleObject+0x14"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_ee_stack(dialog)
        assert cmd == "!EEStack"
        dialog._run_one_command.assert_called_once_with("!EEStack")
        assert "Thread   0" in out
        assert "Thread   3" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("no CLR")
        cmd, out = llm_ee_stack(dialog)
        assert "Error getting EE stacks" in out


class TestNameToEe:
    CANNED_OUTPUT = """\
Module:      00007ff81234abcd
Assembly:    DotnetCrash.dll
Token:       0x02000003
MethodTable: 00007ff81234a005
EEClass:     00007ff81234ef02
Name:        DotnetCrash.Config"""

    def test_basic_call(self, dialog):
        dialog._run_one_command.return_value = self.CANNED_OUTPUT
        cmd, out = llm_name_to_ee(dialog, module="DotnetCrash", typename="DotnetCrash.Config")
        assert cmd == "!Name2EE DotnetCrash DotnetCrash.Config"
        dialog._run_one_command.assert_called_once_with("!Name2EE DotnetCrash DotnetCrash.Config")
        assert "MethodTable" in out

    def test_error_handling(self, dialog):
        dialog._run_one_command.side_effect = RuntimeError("module not found")
        cmd, out = llm_name_to_ee(dialog, module="Bad", typename="Bad.Type")
        assert "Error resolving name" in out


# ---------------------------------------------------------------------------
# Convenience list sanity checks
# ---------------------------------------------------------------------------


def test_ttd_tools_list():
    assert len(TTD_TOOLS) == 4
    names = {json.loads(f.__doc__)["name"] for f in TTD_TOOLS}
    assert names == {
        "ttd_step_back",
        "ttd_travel_to",
        "ttd_query_exceptions",
        "ttd_query_calls",
    }


def test_dotnet_tools_list():
    assert len(DOTNET_TOOLS) == 10
    names = {json.loads(f.__doc__)["name"] for f in DOTNET_TOOLS}
    assert names == {
        "managed_stack",
        "inspect_object",
        "dump_stack_objects",
        "print_exception",
        "dump_heap_stat",
        "dump_heap_type",
        "gc_root",
        "managed_threads",
        "ee_stack",
        "name_to_ee",
    }
