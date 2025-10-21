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

SmallWorld is available as a `pip package <https://pypi.org/project/smallworld-re/>`_ package.

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

Using the full set of SmallWorld's features,
or setting up a complete development environment,
requires a large number of native dependencies. 

.. warning::
   
   SmallWorld is actively in the process of reworking
   its complete installation process.

   Please forgive our appearance while we work to improve this space.
