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
]
