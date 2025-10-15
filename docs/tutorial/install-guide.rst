.. _installation:
Installation Guide
==================

Prerequisites
-------------

SmallWorld is supported by `Python <https://www.python.org/downloads/>`_
(>=3.10) on both Windows and Linux and is installed with `pip
<https://pip.pypa.io/en/stable/>`_. Both Python and pip must be installed on
your system before attempting to install SmallWorld.

.. note::
   SmallWorld is very particular about the versions of its pip dependencies.
   Please install in a `virtual environment <https://docs.python.org/3/library/venv.html>`_.

Basic Installation
------------------

SmallWorld can be installed solely as a Python project.
This will provide access to the Unicorn and angr emulation features.

Ghidra and Panda emulation, plus fuzzing with ``unicornafl``,
requires more dependencies.  See "Complete Installation" for details.

Basic Install from PyPI
***********************

SmallWorld is available as a `pip <https://pypi.org/project/smallworld-re/>`_ package.

It can be installed using

.. code-block:: bash

    pip install smallworld-re

Basic Install from Source
*************************

SmallWorld source is available from  `from GitHub
<https://github.com/smallworld-re/smallworld>`_

To clone the source code, run:

.. code-block:: bash

    git clone git@github.com:smallworld-re/smallworld.git

To perform a basic installation, run the following commands:

.. code-block:: bash

    cd smallworld
    python3 -m pip install -e . -c constraints.txt

Complete Installation
---------------------

Using all of SmallWorld's features requires installing some native packages.

.. note::
   SmallWorld uses specific versions of a number of tools.
   Complete installation may run into problems
   if you have conflicting versions of those tools installed.

.. caution::
   SmallWorld's full development environment is only tested for Ubuntu 22.04 on an amd64 processor:

   * Many of the optional dependencies require Linux, amd64, or both.
   * Some of the optional tools are binary distributions which may be bound to Ubuntu 22.04.
   * For some very strange reason, Ubuntu 22.04 on arm64
     is missing a number of cross-compiler packages needed to build the integration tests.

Complete Install via Script
***************************

The easiest way to perform a complete installation
is to use the script provided in the SmallWorld repository.
This will install SmallWorld in a fresh virtual environment
in ``$HOME/code/venv``.  It requires sudo access
to install packages and to modify a few dependencies.

To clone the source code, run

.. code-block:: bash

   git clone git@github.com:smallworld-re/smallworld.git

To perform a complete installation, run

.. code-block:: bash

   cd smallworld
   ./install.sh

The install script is the authoritative source
for dependencies and the full installation procedure.
