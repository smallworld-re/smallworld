import pickle
import time
import random
import copy
import logging
import os
import pdb
import pyhidra
# Fake out sending run key to filepath for persistence functionality
import smallworld
from smallworld import emulators, state
from smallworld.state.debug import Breakpoint
from smallworld import setup_default_libc, setup_section

smallworld.setup_logging(level=logging.DEBUG)

logger = logging.getLogger(__name__)

pef = "main.exe"

# create a state object and initialize it
cpustate = smallworld.cpus.AMD64CPUState()

# ------------------------------------------------------

logger.info("mapping code into cpu and restricting emulation to known ok regions")

# load and map code into the state
# can't quite see how to get this from ghidra
entry = 0x1400121d0

code = state.PEImage.from_filepath(pef, base=0x140000000, entry=entry, arch="x86", mode="64", format="PE",
        bounds= [
            range(0x1400121d0, 0x140012b0f),   # main
            range(0x140011a00, 0x140011d20),   # info
            range(0x140011360, 0x1400116af),   # ls
        ])

#print(code)
# pdb.set_trace()
# ------------------------------------------------------

logger.info("mapping in user-specified breakpoints")

breaks = {
    0x14013e137: "just before create snapshot",
    0x14013e141: "just after create snapshot call",
    0x1400110a4: "just before process32first",
    # 0x41150c: "just after process32first call",
    # 0x411569: "just before open process",
    # 0x411571: "just after open process"
}

label2break = {}
breakPt = {}
for addr,label in breaks.items():
    brp = Breakpoint(addr, label)
    cpustate.map(brp, f"{addr:x} {label}")
    label2break[label] = brp
    breakPt[addr] = brp
    
# Nb: we can disable / enable breakpoints later with
# breakPt[0x409a20].disable()
# or
# label2break["call to decrypt_strings"].enable()

logger.info("starting pyhidra")

pyhidra.start()
with pyhidra.open_program(pef) as ghidra_flat_api:

    # ------------------------------------------------------

    #logger.info("mapping default libc models")

    # This list of libc fns are the ones we want default hooks for.
    use_windows_api_models = ["CreateToolhelp32Snapshot", "Process32First", "daemon",
                               "flock", "getopt_long", "getpagesize",
                               "getppid", "open", "open64", "printf",
                               "pthread_cond_init", "pthread_cond_signal",
                               "pthread_cond_wait", "pthread_create",
                               "pthread_mutex_init", "pthread_mutex_lock",
                               "pthread_mutex_unlock", "ptrace", "sleep",
                               "srand", "srandom", "strcpy", "__strdup",
                               "strlen", "strncpy", "sysconf", "time",
                               "unlink", "write"]
    #setup_default_libc(ghidra_flat_api, use_windows_api_models, cpustate)
#    pdb.set_trace()
    #code = setup_section(ghidra_flat_api, ".text", cpustate, pef)
    #pdb.set_trace()
    
    cpustate.map(code.code_segments[0])
    
    # ------------------------------------------------------

    logger.info("arranging to skip some fns")

    def skip(pc, cpustate, skipfn):
        logger.info(f".. will skip fn {pc:x} using stub {skipfn}")
        m = smallworld.state.models.Model(pc, skipfn)
        cpustate.map(m, f"skipped_fn{pc:x}")

    def ret0(emu):
        emu.write_register("rax", 0)

    def ret1(emu):
        emu.write_register("rax", 1)

    # for pc in [0x407eb0, 0x4069b0, 0x40f000]:
    #     skip(pc, cpustate, ret1)

    # for pc in [0x411470, 0x4115b0]:
    #     skip(pc, cpustate, ret0)

    # ------------------------------------------------------

    logger.info("set up data, bss, got, argc/argv, and stack")

    # set up the data section
    data_bytes = setup_section(ghidra_flat_api, ".data", cpustate, pef)
    # save a copy for inspection
    with open("encrypted_data_section.dat", "wb") as d:
        d.write(data_bytes)    

    # set up rdata
    setup_section(ghidra_flat_api, ".rdata", cpustate, pef)

    # set up idata
    setup_section(ghidra_flat_api, ".idata", cpustate, pef)

    # set up reloc
    setup_section(ghidra_flat_api, ".reloc", cpustate, pef)

    # set up pdata
    #setup_section(ghidra_flat_api, ".pdata", cpustate, pef)

    setup_section(ghidra_flat_api, ".00cfg", cpustate, pef)

    # set up heap
    heap_address = 0x140142E00
    heap_size = 0x10000
    alloc = smallworld.state.BumpAllocator(address=heap_address, size=heap_size)
    alloc.value = b'\0' * heap_size
    cpustate.map(alloc, "heap")

    cmdline_str = "./main.exe"
    argv = [arg.encode("utf-8") for arg in cmdline_str.split()]
    stack_address = 0x7FFDF0000000
    stack = state.Stack.initialize_stack(argv=argv, address=stack_address, size=0x10000)
    cpustate.map(stack, "stack")

    # argc and argv are in these regs at start of main
    cpustate.edi.value = stack.get_argc()
    cpustate.rsi.value = stack.get_argv()
    cpustate.rsp.value = stack.get_stack_pointer()
    logger.info(hex(cpustate.rsp.value))
    
    ###############################################################################
    
    logger.info("creating emulator")

    emu = emulators.UnicornEmulator(cpustate.arch, cpustate.mode, "little")
    emu.load(code)

    # set entry point
    cpustate.rip.value = entry
    pdb.set_trace()
    cpustate.apply(emu)

    
    # tick()
    j=0
    while True:

        j += 1

        pc = emu.read_register("pc")
        print(f"PC: {hex(pc)}")
        instr = emu.current_instruction()
        logger.info(f"emulated instr {j} {pc:x} {instr}")

        done = emu.step()
        print('reached')
        if done:
            break

