import sys
from pathlib import Path

# pytest prepends the project root to sys.path, which makes redforge.py
# shadow the redforge package in src/. Always put src/ at position 0.
_src = str(Path(__file__).parent / "src")
if sys.path[0] != _src:
    sys.path.insert(0, _src)


def _clear_redforge_module_shadow() -> None:
    mod = sys.modules.get("redforge")
    if mod is not None and not hasattr(mod, "__path__"):
        del sys.modules["redforge"]


_clear_redforge_module_shadow()


def pytest_runtest_setup(item):
    _clear_redforge_module_shadow()
