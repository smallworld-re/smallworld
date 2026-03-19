.. _installation_pypi:

Minimal Install with PyPI
=========================

SmallWorld can be installed solely as a Python project.
This will provide access to the Unicorn and angr emulation features immediately,
as well as Ghidra with a tiny bit of work.

This is sufficient to write and test emulation harnesses.
Fuzzing with SmallWorld will require the Nix or Docker installation.

Prerequisites
-------------

SmallWorld is supported by `Python <https://www.python.org/downloads/>`_
(>=3.12) on Linux and is installed with `pip
<https://pip.pypa.io/en/stable/>`_. Both Python and pip must be installed on
your system before attempting to install SmallWorld.

.. note::
   SmallWorld is very particular about the versions of its pip dependencies.
   Please install in a `virtual environment <https://docs.python.org/3/library/venv.html>`_.

Basic Install from PyPI
-----------------------

SmallWorld is available as a `pip package <https://pypi.org/project/smallworld-re/>`_ package.

It can be installed by running the following:

.. code-block:: bash

    pip install smallworld-re[emu-angr,emu-unicorn]

If you experience problems with ``angr`` or ``unicorn``,
you can omit the ``emu-angr`` or ``emu-unicorn`` from the command.
SmallWorld will still work, except it won't include the omitted backend.

Basic Install from Source
-------------------------

SmallWorld source is available from  `from GitHub
<https://github.com/smallworld-re/smallworld>`_

To clone the source code, run:

.. code-block:: bash

    git clone git@github.com:smallworld-re/smallworld.git

To perform a basic installation, run the following commands:

.. code-block:: bash

    cd smallworld
    python3 -m pip install -e .[emu-angr,emu-unicorn]


Adding Ghidra Support
---------------------

.. warning::

   The installation procedure for ``pyghidra`` does not appear to be stable,
   and the docs inside of Ghidra itself are wrong as of this writing.

   This procedure works for Ghidra 11.3.2, but will not be actively tested
   by SmallWorld moving forward.

As a prerequisite, you will need Ghidra 11.3.2 or later installed,
as well as an appropriate Java JDK.
See the `Ghidra documentation <https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md>`_
for details.

Assuming the ghidra installation directory is at ``GHIDRA_INSTALL_DIR``,
execute the follwing in your SmallWorld environment:

.. code-block:: bash

    python3 -m pip install --no-index -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra


Compiling Example Binaries
--------------------------

SmallWorld no longer supports compiling the example binaries outside of the Nix environment.

Some example harnesses are extremely sensitive to variations between compilers,
or even versions of the same compiler.  Attempting to duplicate
the necessary environment outside of Nix is absolutely possible,
but is not recommended or supported.
