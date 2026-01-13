.. _installation_nix:

Full Installation with Nix
==========================

`Nix <https://nixos.org/>`_ is a "declarative build environment".
Think of it like Python virtualenv, but it also works for native binaries,
and is far stricter in defining dependencies.

Activating the Nix environment drops you into a new shell.
You will have access to all programs normally available on your computer,
but will also have tools like AFL++, Panda, and the cross compilers
required by SmallWorld.  You will also be in a managed Python environment
with SmallWorld already configured.

.. note::

   The Python environment built by Nix will override any virtualenv or similar
   that you had outside of Nix.  You will have to re-import
   any other packages you want to use in conjunction with SmallWorld.
   See below for more details.
 

Prerequisites
-------------

The only prerequisite for the Nix environment is `Nix <https://nixos.org/>`_ itself 
with flakes enabled. We recommend the `Determinate Systems nix installer
<https://docs.determinate.systems/determinate-nix/>`_.

Full Install as a Nix Package
-----------------------------

.. warning::
   
   TODO: We currently don't publish a Nix package.

Full Install from Source
------------------------

.. note::

   This approach requires full internet access to pull down
   SmallWorld's dependencies from Nix.

SmallWorld source is available from  `from GitHub
<https://github.com/smallworld-re/smallworld>`_

To clone the source code, run:

.. code-block:: bash

    git clone git@github.com:smallworld-re/smallworld.git

From there, you have a choice of two Nix environments.
Follow the instructions in one of the following sections
to activate the shell you want.

.. note::

   These two environments don't coexist peacefully.
   Please pick one that suits your needs, and stick with it.

Imperative Environment
**********************

The imperative environment is designed for users;
it will present you with a Python venv that's pre-populated
with SmallWorld and all of its dependencies.

The following command will open a nix shell
with the imperative environment configured:

.. code-block:: bash

    cd smallworld
    nix develop.#imperative

You can access ``pip`` using ``uv pip`` as the base command,
and are free to install your own packages.
These will not modify SmallWorld's configuration,
and will persist if you close and reopen the nix imperative shell.

Development Environment
***********************

The development environment is designed for SmallWorld developers.
It offers more features for tracking changes to the SmallWorld environment,
at the cost of some flexibility.

The following command will open a nix shell
with the develipment environment configured:

.. code-block:: bash
    
    cd smallworld
    nix develop

The only difference here is that you must use ``uv`` to manage the Python environment.
Changes to your python environment are tracked by ``uv``,
and will automatically update ``pyproject.toml``,
as well as the nix configuration in order to track native libraries.

Building Example Binaries
-------------------------

To build all examples, execute the following:

.. code-block:: bash

   nix build .#tests
   tar -C tests -xvf result/test_binaries.tar

