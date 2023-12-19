# type: ignore

import sys

import angr


class SmallWorldMemoryPlugin(angr.storage.DefaultMemory):
    def _default_value(
        self,
        addr,
        size,
        name=None,
        inspect=True,
        events=True,
        key=None,
        fill_missing: bool = True,
        **kwargs,
    ):
        print("Our plugin is called")
        print(
            f"Address: {addr} Size: {size} Name: {name} Inspect: {inspect} Events: {events} Key: {key} fill_missing: {fill_missing} kwargs: {kwargs}"
        )
        return super()._default_value(
            addr,
            size,
            name,
            inspect=inspect,
            events=events,
            key=key,
            fill_missing=fill_missing,
            **kwargs,
        )


class SWMemory(SmallWorldMemoryPlugin):
    def __init__(self):
        super().__init__(memory_id="mem")


class SWRegisters(SmallWorldMemoryPlugin):
    def __init__(self):
        super().__init__(memory_id="reg")


stack_size = 1024 * 1024 * 8
stack_perms = 1 | 2 | 4

binary_path = sys.argv[1]
print(f"Loading {binary_path}")
proj = angr.Project(binary_path, main_opts={"backend": "blob", "arch": "x86_64"})

state = angr.SimState(
    project=proj, arch="x86_64", stack_size=stack_size, stack_perms=stack_perms
)

state.register_plugin("memory", SWMemory(), inhibit_init=True)
state.register_plugin("registers", SWRegisters(), inhibit_init=True)

# We have to do our loading manually
code = open(binary_path, "rb")
code_bytes = code.read()
code.close()
state.memory.store(0, code_bytes)

state.step()
