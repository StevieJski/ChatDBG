"""
Standalone tool functions for TTD (Time Travel Debugging) and .NET/SOS
diagnostics in WinDbg.

These are meant to be mixed into the WinDbgDialog class. Each function
takes `self` as the first parameter (the dialog instance) and calls
`self._run_one_command()` to execute debugger commands.

Each function follows the llm_* convention:
  - JSON schema in the docstring (parsed by Assistant._add_function)
  - Returns a (command_repr, output_string) tuple
"""


# ---------------------------------------------------------------------------
# TTD (Time Travel Debugging) tools
# ---------------------------------------------------------------------------


def llm_ttd_step_back(self, steps: int = 1):
    """
    {
        "name": "ttd_step_back",
        "description": "Step backward in the TTD trace by the specified number of steps. Use this to rewind execution and verify hypotheses about when values changed.",
        "parameters": {
            "type": "object",
            "properties": {
                "steps": {
                    "type": "integer",
                    "description": "Number of steps to go backward. Defaults to 1."
                }
            },
            "required": []
        }
    }
    """
    steps = max(1, int(steps))
    output = ""
    try:
        for _ in range(steps):
            output = self._run_one_command("t-")
    except Exception as e:
        return f"t- (x{steps})", f"Error stepping back: {e}"
    return f"t- (x{steps})", output


def llm_ttd_travel_to(self, position: str):
    """
    {
        "name": "ttd_travel_to",
        "description": "Travel to a specific position in the TTD trace timeline. Positions are in the format 'N:N' (e.g., '35:12').",
        "parameters": {
            "type": "object",
            "properties": {
                "position": {
                    "type": "string",
                    "description": "The timeline position to travel to, in 'N:N' format (e.g., '35:12')."
                }
            },
            "required": [ "position" ]
        }
    }
    """
    cmd = f"!tt {position}"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error traveling to position: {e}"
    return cmd, output


def llm_ttd_query_exceptions(self):
    """
    {
        "name": "ttd_query_exceptions",
        "description": "Query all exceptions that occurred during the recorded TTD trace. Returns exception types, codes, and timeline positions.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = 'dx @$curprocess.TTD.Events.Where(t => t.Type == "Exception")'
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error querying exceptions: {e}"
    return cmd, output


def llm_ttd_query_calls(self, function_name: str):
    """
    {
        "name": "ttd_query_calls",
        "description": "Query all calls to a specific function recorded in the TTD trace, including arguments, return values, and timeline positions.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "The name of the function to query calls for (e.g., 'kernel32!CreateFileW')."
                }
            },
            "required": [ "function_name" ]
        }
    }
    """
    cmd = f'dx @$curprocess.TTD.Calls("{function_name}")'
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error querying calls: {e}"
    return cmd, output


# ---------------------------------------------------------------------------
# .NET / SOS diagnostic tools
# ---------------------------------------------------------------------------


def llm_managed_stack(self):
    """
    {
        "name": "managed_stack",
        "description": "Get the managed (.NET) call stack with arguments and local variables. Shows the CLR stack frames with method names and parameter values.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!CLRStack -a"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error getting managed stack: {e}"
    return cmd, output


def llm_inspect_object(self, address: str):
    """
    {
        "name": "inspect_object",
        "description": "Inspect a .NET object at the given memory address. Shows the object's type, fields, values, method table, and size.",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "The memory address of the .NET object to inspect (e.g., '000001c4a8032fd0')."
                }
            },
            "required": [ "address" ]
        }
    }
    """
    cmd = f"!DumpObj {address}"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error inspecting object: {e}"
    return cmd, output


def llm_dump_stack_objects(self):
    """
    {
        "name": "dump_stack_objects",
        "description": "List all .NET objects on the current thread's stack. Useful for finding managed objects that may be relevant to the current error.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!DumpStackObjects"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error dumping stack objects: {e}"
    return cmd, output


def llm_print_exception(self):
    """
    {
        "name": "print_exception",
        "description": "Print the current managed exception with the full inner exception chain. Use this first when a .NET exception is the crash cause — it shows exception type, message, HResult, and nested inner exceptions.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!pe -nested"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error printing exception: {e}"
    return cmd, output


def llm_dump_heap_stat(self):
    """
    {
        "name": "dump_heap_stat",
        "description": "Show .NET managed heap statistics grouped by type. Displays object count and total size for each type. Useful for identifying memory leaks or unexpected object accumulation.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!DumpHeap -stat"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error dumping heap stats: {e}"
    return cmd, output


def llm_dump_heap_type(self, typename: str):
    """
    {
        "name": "dump_heap_type",
        "description": "Find all instances of a specific .NET type on the managed heap. Returns addresses, method tables, and sizes. Use this after dump_heap_stat to drill into a suspicious type.",
        "parameters": {
            "type": "object",
            "properties": {
                "typename": {
                    "type": "string",
                    "description": "The full .NET type name to search for (e.g., 'System.String' or 'MyApp.Config')."
                }
            },
            "required": [ "typename" ]
        }
    }
    """
    cmd = f"!DumpHeap -type {typename}"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error dumping heap for type: {e}"
    return cmd, output


def llm_gc_root(self, address: str):
    """
    {
        "name": "gc_root",
        "description": "Trace GC roots for a .NET object — shows why the object is alive. Displays the reference chain from root (stack, handle table, static) to the target object. Essential for diagnosing memory leaks.",
        "parameters": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "The memory address of the .NET object to trace roots for (e.g., '000001c4a8033040')."
                }
            },
            "required": [ "address" ]
        }
    }
    """
    cmd = f"!GCRoot {address}"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error tracing GC roots: {e}"
    return cmd, output


def llm_managed_threads(self):
    """
    {
        "name": "managed_threads",
        "description": "List all managed .NET threads with their state, GC mode, exception info, apartment type, and lock count. Use this to get an overview of thread activity and find threads with unhandled exceptions.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!Threads"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error listing managed threads: {e}"
    return cmd, output


def llm_ee_stack(self):
    """
    {
        "name": "ee_stack",
        "description": "Show managed call stacks for ALL .NET threads at once. Useful for deadlock analysis and getting a complete picture of what every managed thread is doing.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
    """
    cmd = "!EEStack"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error getting EE stacks: {e}"
    return cmd, output


def llm_name_to_ee(self, module: str, typename: str):
    """
    {
        "name": "name_to_ee",
        "description": "Resolve a .NET type or method name to its internal runtime addresses (MethodTable, EEClass). Use this to look up a type before using inspect_object or dump_heap_type.",
        "parameters": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "The module name containing the type (e.g., 'DotnetCrash' or 'System.Private.CoreLib')."
                },
                "typename": {
                    "type": "string",
                    "description": "The full type or method name to resolve (e.g., 'DotnetCrash.Config' or 'System.String')."
                }
            },
            "required": [ "module", "typename" ]
        }
    }
    """
    cmd = f"!Name2EE {module} {typename}"
    try:
        output = self._run_one_command(cmd)
    except Exception as e:
        return cmd, f"Error resolving name: {e}"
    return cmd, output


# ---------------------------------------------------------------------------
# Convenience lists for conditional registration
# ---------------------------------------------------------------------------

TTD_TOOLS = [
    llm_ttd_step_back,
    llm_ttd_travel_to,
    llm_ttd_query_exceptions,
    llm_ttd_query_calls,
]

DOTNET_TOOLS = [
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
]
