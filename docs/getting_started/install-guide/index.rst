.. _installation:

Installation Guide
==================

SmallWorld offers three separate installation methods:

.. toctree::
   :titlesonly:

   pypi
   nix
   docker 

Enabling all of SmallWorld's features requires specific dependencies
that are very difficult to install reliably on different platforms.
Thus, we strongly recommend using Nix or Docker.

The following features are only available via Nix or Docker:

    - Building the test and example binaries
    - Emulating using Panda
    - Fuzzing using ``unicornafl``
