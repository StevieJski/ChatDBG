"""
CDB subprocess wrapper — launches CDB with piped stdin/stdout and provides
synchronous command execution via marker-based output delimiting.

Based on patterns from PyCDB (fishstiqz/pycdb) and mcp-windbg (svnscha/mcp-windbg).
"""

import re
import subprocess
import sys
import threading
import uuid


# Regex matching the CDB prompt, e.g. "0:000> " or "1:023> "
_PROMPT_RE = re.compile(r"^\s*\d+:\d{3}>\s*$")

# Commands that resume target execution (not safe for marker-based execute())
_CONTINUE_CMDS = {"g", "go", "t", "p", "pt", "pa", "tt", "ta", "gh", "gn"}


class CDBSession:
    """Interactive CDB session driven over stdin/stdout pipes."""

    def __init__(self, target_exe, target_args=None, cdb_exe="cdb",
                 initial_commands=None, dump_file=None):
        """
        Launch CDB as a subprocess.

        Parameters
        ----------
        target_exe : str
            Path to the executable to debug, or None if using a dump file.
        target_args : list[str], optional
            Arguments to pass to the target executable.
        cdb_exe : str
            Path to the CDB executable (default: "cdb", found on PATH).
        initial_commands : list[str], optional
            Commands to send after CDB starts but before returning control.
        dump_file : str, optional
            Path to a crash dump file to open instead of a live target.
        """
        cmd = [cdb_exe, "-lines", "-2"]
        if dump_file:
            cmd += ["-z", dump_file]
        else:
            cmd.append(target_exe)
            if target_args:
                cmd.extend(target_args)

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

        # Buffer and synchronisation for the reader thread
        self._buf_lock = threading.Lock()
        self._stdin_lock = threading.Lock()
        self._buf = []  # list of output lines
        self._marker_event = threading.Event()
        self._current_marker = None
        self._at_prompt = threading.Event()

        # Start the reader daemon (clear prompt event first to avoid race)
        self._at_prompt.clear()
        self._reader = threading.Thread(target=self._reader_thread, daemon=True)
        self._reader.start()

        # Wait for CDB's initial banner / prompt
        if not self._at_prompt.wait(timeout=30):
            raise TimeoutError("CDB did not present a prompt within the timeout.")

        # Disable output paging to prevent readline() from blocking
        self.execute(".lines -1")

        # Run any initial setup commands
        if initial_commands:
            for cmd_str in initial_commands:
                base_cmd = cmd_str.strip().split()[0].lower()
                if base_cmd in _CONTINUE_CMDS:
                    # Execution-continuation commands: send raw and wait
                    # for CDB to hit a break (exception/breakpoint/exit)
                    self._send(cmd_str)
                    self._at_prompt.clear()
                    with self._buf_lock:
                        self._buf.clear()
                    if not self._at_prompt.wait(timeout=120):
                        raise TimeoutError(
                            f"CDB did not break after '{cmd_str}' within 120s."
                        )
                else:
                    self.execute(cmd_str)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, command, timeout=120):
        """
        Send a command to CDB and return its text output.

        A unique marker is appended after the command so we can reliably
        detect where the output ends.
        """
        marker = f"CHATDBG_CMD_DONE_{uuid.uuid4().hex}"

        # Reset state atomically relative to the reader thread
        with self._buf_lock:
            self._marker_event.clear()
            self._at_prompt.clear()
            self._buf.clear()
            self._current_marker = marker

        # Send the command followed by the echo marker
        self._send(command)
        self._send(f".echo {marker}")

        # Wait for the marker to appear in stdout
        if not self._marker_event.wait(timeout=timeout):
            raise TimeoutError(
                f"CDB did not respond within {timeout}s for command: {command}"
            )

        # Collect the buffered output (everything before the marker line)
        with self._buf_lock:
            output = "\n".join(self._buf)
            self._buf.clear()
            self._current_marker = None

        return self._clean_output(output, command, marker)

    def wait_for_break(self, timeout=60):
        """
        Wait for CDB to hit a breakpoint or exception and return all output
        up to the break prompt.
        """
        self._at_prompt.clear()
        with self._buf_lock:
            self._buf.clear()

        if not self._at_prompt.wait(timeout=timeout):
            raise TimeoutError("CDB did not break within the timeout period.")

        with self._buf_lock:
            output = "\n".join(self._buf)
            self._buf.clear()

        return output

    def close(self):
        """Terminate the CDB subprocess."""
        if self._proc.poll() is None:
            try:
                self._send("q")
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
                try:
                    self._proc.wait(timeout=5)
                except Exception:
                    pass

    @property
    def is_alive(self):
        return self._proc.poll() is None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send(self, text):
        """Write a line to CDB's stdin."""
        with self._stdin_lock:
            try:
                self._proc.stdin.write((text + "\n").encode("utf-8"))
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def _reader_thread(self):
        """
        Daemon thread that continuously reads CDB stdout line-by-line,
        buffers output, and signals when markers or prompts are detected.
        """
        try:
            for raw_line in iter(self._proc.stdout.readline, b""):
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")

                # Check for marker
                with self._buf_lock:
                    if self._current_marker and self._current_marker in line:
                        self._marker_event.set()
                        continue
                    self._buf.append(line)

                # Check for CDB prompt (secondary signal)
                if _PROMPT_RE.match(line.strip()):
                    self._at_prompt.set()
        except Exception:
            pass

    def _clean_output(self, output, command, marker):
        """
        Remove the echoed command, marker echo line, and CDB prompt lines
        from the captured output.
        """
        lines = output.split("\n")
        cleaned = []
        command_echo_stripped = False
        for line in lines:
            stripped = line.strip()
            # Skip the first occurrence of the echoed command
            if not command_echo_stripped and stripped == command.strip():
                command_echo_stripped = True
                continue
            # Skip marker remnants
            if marker in stripped:
                continue
            # Skip bare CDB prompt lines
            if _PROMPT_RE.match(stripped):
                continue
            cleaned.append(line)

        # Trim leading/trailing blank lines
        while cleaned and not cleaned[0].strip():
            cleaned.pop(0)
        while cleaned and not cleaned[-1].strip():
            cleaned.pop()

        return "\n".join(cleaned)
