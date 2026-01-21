.. _tutorial_vxworks:

Loading a VXWorks image
=======================

.. warning::

    Loading VXWorks images requires a license to Binary Ninja Ultimate

In this tutorial, you will be guided through loading a VXWorks file.

It is important to know VXWorks files can differ based on VXWorks version and 
specific compiler options. For this example, we will use a VXWorks binary 
published in the vxhunter github repository. 
:ref: https://github.com/PAGalaxyLab/vxhunter/tree/master/example_firmware

In most cases, we will not have access to the source code of the VXWorks binary.
This applies for this tutorial as well, but we will focus on the loading process.


In order to aid analysis of our VXWorks binary,
we want to find the symbol table. Vector35 details the
heuristics Binary Ninja uses to find the symbol table in their blog
here: :ref:`https://binary.ninja/2024/10/31/introducing-vxworks.html`.

Using the VXWorks loader
-------------------

SmallWorld includes a model of the basic features of a VXWorks loader.
To exercise it, you will need to use ``Executable.from_vxworks()``, described in :ref:`memory`.

Unlike other executable formats, VXWorks images do not have standardized
metadata to specify base addresses or load addresses. However,
Binary Ninja can attempt to infer the address. In some cases, this may be incorrect.
If the user chooses to manually specify a load address, SmallWorld will
prefer the user's input over Binary Ninja's heuristic.

.. code-block:: python

    filepath = "path/to/image_vx6_arm_little_endian.bin"
    with open(filepath, "rb") as f:
        code = smallworld.state.memory.code.Executable.from_vxworks(f)
        machine.add(code)

