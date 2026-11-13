"""
FABEO Tests Package
"""
import sys
import os
import types

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if "FABEO" not in sys.modules:
    pkg = types.ModuleType("FABEO")
    pkg.__path__ = [ROOT_DIR]
    pkg.__file__ = os.path.join(ROOT_DIR, "__init__.py")
    sys.modules["FABEO"] = pkg
