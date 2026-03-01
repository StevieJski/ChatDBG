"""
ChatDBG pykd bridge client — runs in Python 3.11+ as a subprocess.

Injects the pykd proxy into sys.modules so that chatdbg_windbg.py can
``import pykd`` transparently, then runs the normal ChatDBG WinDbg flow.

Launched by pykd_bridge_server.py.  Requires CHATDBG_PYKD_PORT env var.
"""

import os
import sys

# Inject the proxy as the 'pykd' module before anything imports it
from chatdbg import pykd_bridge_proxy

sys.modules["pykd"] = pykd_bridge_proxy

# Now import and run chatdbg_windbg normally
from chatdbg.chatdbg_windbg import chatdbg_windbg_init, why_handler

chatdbg_windbg_init()

if len(sys.argv) > 1:
    why_handler(" ".join(sys.argv[1:]))
else:
    why_handler("")
