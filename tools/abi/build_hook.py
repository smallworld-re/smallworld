"""setuptools hook: generate ``smallworld/platforms/abi/_data`` in build_py.

pyproject.toml wires it in with::

    [tool.setuptools.cmdclass]
    build_py = "tools.abi.build_hook.BuildPy"

* Wheel builds (``python -m build``, ``pip install .``, ``uv build``, nix)
  write the package into build_lib, so it lands in the wheel and never
  touches the source tree. The source tree's own ``_data`` (from an earlier
  editable build) is excluded from the package list, so a stale copy is
  never shipped.
* Editable builds (``pip install -e .``, ``uv pip install -e .``, ``uv
  sync``) map ``smallworld`` to the source tree, so the package is written
  in-tree (gitignored), like ``build_ext --inplace``, and also reported in
  build_lib for strict editable installs, whose link tree is built from
  there. An editable build that generates no tables (Python 3.9 or 3.11,
  or the opt-out) leaves real in-tree tables alone, warning if their inputs
  changed.
"""

import importlib.util
import os
import shutil
import typing

from setuptools.command.build_py import build_py as _build_py
from setuptools.errors import ExecError

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def _generator() -> typing.Any:
    spec = importlib.util.spec_from_file_location(
        "_smallworld_abi_generate", os.path.join(HERE, "generate.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BuildPy(_build_py):
    """``build_py`` that also generates the ABI tables."""

    _abi_outputs: typing.List[str] = []

    def run(self) -> None:
        super().run()
        generator = _generator()
        editable = bool(getattr(self, "editable_mode", False))
        root = ROOT if editable else self.build_lib
        out = os.path.join(root, generator.DATA_REL)
        self.announce(f"generating the ABI tables into {out}", level=2)
        try:
            files = generator.generate(
                out,
                src_root=ROOT,
                editable=editable,
                log=lambda m: self.announce(m, level=2),
            )
            if editable:
                # A strict editable install (editable_mode=strict) serves a
                # link tree built from what build_py reports in build_lib, not
                # the source tree, so report a copy there as well; the lenient
                # modes ignore it and import the in-tree copy.
                out = os.path.join(self.build_lib, generator.DATA_REL)
                if os.path.isdir(out):
                    shutil.rmtree(out)
                os.makedirs(out)
                for name in files:
                    shutil.copy2(os.path.join(ROOT, generator.DATA_REL, name), out)
        except (generator.GeneratorError, OSError) as e:
            raise ExecError(f"{generator.PREFIX}: {e}") from None
        self._abi_outputs = [os.path.join(out, name) for name in files]

    def get_outputs(self, include_bytecode: bool = True) -> typing.List[str]:
        outputs = list(super().get_outputs(include_bytecode))
        return outputs + list(self._abi_outputs)
