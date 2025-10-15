Contributing to SmallWorld
==========================

We'd love to have people contribute to SmallWorld.
It's a fully open-source project, and we welcome
pull requests on `GitHub <https://github.com/smallworld-re/smallworld>`_.

Contribution Lifecycle
----------------------

SmallWorld follows a very standard GitHub contribution life cycle.

For external contributors, it works as follows:

    1. Create a fork of the SmallWorld repository

    2. Clone your fork

    3. Set up your development environment

    4. Develop your feature or fix

    5. Push your work to a branch on your fork

    6. Open a PR on the root SmallWorld repository, merging your branch into main.

    7. While the PR is not accepted, address feedback and failed tests.

    8. Celebrate!

Members of the smallworld organization can work directly off of branches
on the root repository, rather than having to create a fork.

Development Environment
-----------------------

The "Complete Installation" section of the :ref:`installation`
will set up a full development environment environment for SmallWorld.

.. caution::
   SmallWorld's full development environment is only tested for Ubuntu 22.04 on an amd64 processor:

   * Many of the optional dependencies require Linux, amd64, or both.
   * Some of the optional tools are binary distributions which may be bound to Ubuntu 22.04.
   * For some very strange reason, Ubuntu 22.04 on arm64
     is missing a number of cross-compiler packages needed to build the integration tests.

   Development on other platforms is possible
   if you only need Unicorn and angr, and rely on the CI/CD server to run tests.

Code Style
----------

SmallWorld uses a few code style tools to help with basic maintenance.
These can be installed as pre-commit hooks.  To enable, run:

.. code-block:: bash

   pre-commit install

This will force you to address linter, bug checker, and typechecker errors before committing.
The CI/CD process will reject a PR that doesn't pass the linter checks.

.. caution::
   
   Rarely, a branch may pass linting locally, but fail when linted on CI/CD.
   Contact the SmallWorld team if this happens.

Testing
-------

SmallWorld includes both unit tests to exercise basic non-emulation features,
and integration tests to exercise the emulators themselves.

The rules: 

    1. If you add a feature, add a test case.
    2. If you find a bug, fix it, and add a test case.
    3. If you add a test case, exercise all relevant platforms and emulators.

Unit Tests
**********

SmallWorld's unit tests live in ``smallworld/tests/unit.py``.

This is your bog-standard unit test suite built using Python's unit test package.
Add a test here if you add a new data structure or non-emulation feature.

Integration Tests
*****************

SmallWorld's integration tests are a collection of self-contained harness scripts
found in the subdirectories of ``smallworld/tests``.

These exercise specific features of the SmallWorld toolkit.
These serve as a combination test suite and example library.

Add test cases here to exercise one of the following:

    * A new feature of an emulator
    * A new analysis
    * A new library function model
    * A bug found and fixed in an emulator

In general, exercise the test case for as many platforms as are relevant.
If it's a basic feature test, test for each relevant platform/emulator pair.
This equates to a ton of test scripts, but they will share a huge amount of code.
``xargs | sed -i`` is your friend.

The actual driver for the integration tests is at ``smallworld/tests/integration.py``.
This uses Python's unit test package to drive the individual scripts.
By now, there are plenty of examples to copy from.

.. caution::

   Do not try to run the complete integration test suite locally.
   
   As of this writing, there are over 1800 test scripts,
   which ``integration.py`` does not parallelize.
   It can take over a day for the test suite to run manually.

   Run any immediately-relevant tests yourself,
   and allow the CI/CD system to run the rest.
   It's set up in parallel, and will take less than 20 minutes to complete. 

Compiling the Integration Tests
*******************************

SmallWorld's test suite includes a very large number of example programs.
If you installed via the installer script,
the necessary toolchains will already be installed on your computer.

If you did not install via the script, then your system probably can't support
building the integration test suite.

To build the test binaries, run the following:

.. code-block:: bash
   
   cd smallworld/tests
   make clean all               # Make the main integration tests
   ulimit -c unlimited          # Enable core dumps
   make -C ./elf_core clean all # Build the ELF core dump tests

.. caution::
    
   If you set up your development environment in a docker container,
   you may not be able to build the elf core tests,
   due to how Docker overrides the ``ulimit`` command.

Pull Requests
-------------

Creating a pull request for SmallWorld works as normal for GitHub.

A memeber of the SmallWorld team will have to vet each commit in your PR
before it's approved to run through CI/CD.  Please be patient with us.

Once approved, the system will automatically run all linters, unit tests and integration tests.
This total process can take between ten and twenty minutes depending on system load.
