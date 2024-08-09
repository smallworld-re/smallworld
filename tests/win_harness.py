import logging

import pyhidra

import smallworld
from smallworld import emulators, setup_default_windows, state
from smallworld.state.debug import Breakpoint

smallworld.setup_logging(level=logging.DEBUG)

logger = logging.getLogger(__name__)

pef = "main.exe"

# create a state object and initialize it
cpustate = smallworld.cpus.AMD64CPUState()

# ------------------------------------------------------

logger.info("mapping code into cpu and restricting emulation to known ok regions")

# load and map code into the state
# entry = 0x1400121D0  # main
# entry = 0x140011000  # ps
entry = 0x140011360  # ls
# entry = 0x140011d30   # persist

code = state.PEImage.from_filepath(
    pef, base=0x140000000, entry=entry, arch="x86", mode="64", format="PE"
)
# bounds= [
#     range(0x1400121d0, 0x140012b0f),   # main
#     range(0x140011a00, 0x140011d20),   # info
#     range(0x140011360, 0x1400116af),   # ls
#     range(0x1400121a0, 0x1400121b7),   # uninstall
#     range(0x140011000, 0x14001134b),   # ps
# ])

# print(code.data_segments[0])
# pdb.set_trace()
# ------------------------------------------------------

logger.info("mapping in user-specified breakpoints")

breaks = {
    0x140011037: "just before create snapshot",
    0x140011039: "just after create snapshot call",
    0x1400110A4: "just before process32first",
}

label2break = {}
breakPt = {}
for addr, label in breaks.items():
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

    def skip(pc, cpustate, skipfn):
        logger.info(f".. will skip fn {pc:x} using stub {skipfn}")
        m = smallworld.state.models.Model(pc, skipfn)
        cpustate.map(m, f"skipped_fn{pc:x}")

    def ret0(emu):
        emu.write_register("rax", 0)

    def ret1(emu):
        emu.write_register("rax", 1)

    # ------------------------------------------------------

    # logger.info("mapping default libc models")

    # This list of windows fns are the ones we want default hooks for.
    use_windows_api_models = [
        "std::vector<>::vector<>",
        "strtok",
        "std::vector<>::push_back",
        "std::basic_string<>::basic_string<>",
        "std::basic_string<>::length",
        "std::allocator<>::allocator<>",
        "CreateToolhelp32Snapshot",
        "Process32FirstW",
        "Process32NextW",
        "CloseHandle",
        "OpenProcess",
        "DeleteFileW",
        "atoi",
        "WSAStartup",
        "WSACleanup",
        "socket",
        "connect",
        "recv",
        "closesocket",
        "ProcessIdToSessionId",
        "GetCurrentDirectoryA",
        "GetVersion",
        "FindClose",
        "memset",
        "FindFirstFileA",
        "[]",
        "FindNextFileA",
        "GetComputerName",
        "GetUserName",
        "RegCreateKeyExA",
        "RegSetValueExA",
        "RegGetValueA",
    ]

    # pdb.set_trace()
    # program = ghidra_flat_api.getCurrentProgram()
    # listing = program.getListing()
    # logger.debug(f"LISTING: {[x.getName() for x in listing.getFunctions(True)]}")

    cpustate.map(code.code_segments[0])

    for data in code.data_segments:
        cpustate.map(data)

    setup_default_windows(ghidra_flat_api, use_windows_api_models, cpustate, pef)

    # ------------------------------------------------------
    for pc in [0x14001102B, 0x1400121F4, 0x14001138E, 0x140012532]:
        vector = state.models.AMD64MicrosoftStdVectorModel(pc)
        cpustate.map(vector)

    for pc in [0x1400124D9, 0x1400113F4]:
        string = state.models.AMD64MicrosoftStdStringModel(pc)
        cpustate.map(string)

    string_len = state.models.AMD64MicrosoftStdStringLengthModel(0x1400124E7)
    cpustate.map(string_len)

    for pc in [0x140012218, 0x140012246, 0x140012279, 0x14001254F, 0x14001257C]:
        strtok = state.models.AMD64MicrosoftStrtokModel(pc)
        cpustate.map(strtok)
    #     skip(pc, cpustate, ret0)

    # for pc in [0x14001225c, 0x140012261]:
    #     skip(pc, cpustate, ret1)

    # push_back = state.models.Model(0x140012237, state.models.AMD64MicrosoftVectorPushBackModel)
    # cpustate.map(push_back)
    skip(0x140012237, cpustate, ret0)
    skip(0x14001256E, cpustate, ret0)

    skip(0x140073AA4, cpustate, ret1)  # Process32FirstW

    open_proc = state.models.AMD64MicrosoftOpenProcessModel(0x1400110FF)
    cpustate.map(open_proc)

    for pc in [0x140011118, 0x140011125, 0x140011134]:
        skip(pc, cpustate, ret0)  # <<

    for pc in [0x14001225C, 0x14001233C, 0x1400124FA]:
        bracket = state.models.AMD64MicrosoftBracketOperatorModel(pc)
        cpustate.map(bracket)

    snap = state.models.AMD64MicrosoftCreateSnapshotModel(0x140073A9E)
    cpustate.map(snap)

    proc2sess = state.models.AMD64MicrosoftProcessIdToSessionIdModel(0x14001115B)
    cpustate.map(proc2sess)

    closehandle = state.models.AMD64MicrosoftCloseHandleModel(0x1400111BB)
    cpustate.map(closehandle)

    for pc in [0x14013E148, 0x140073AAA]:
        procNext = state.models.AMD64MicrosoftProcess32NextModel(pc)
        cpustate.map(procNext)

    atoi = state.models.AMD64MicrosoftAToIModel(0x140012281)
    cpustate.map(atoi)

    dir = state.models.AMD64MicrosoftGetCurrentDirectoryAModel(0x1400113A1)
    cpustate.map(dir)

    delete = state.models.AMD64MicrosoftDeleteFileWModel(0x140011762)
    cpustate.map(delete)

    stdalloc = state.models.AMD64MicrosoftStdAllocatorModel(0x14001258D)

    cpustate.map(stdalloc)

    for pc in [0x140012261, 0x14001227E]:
        skip(pc, cpustate, ret1)

    # wsastart = state.models.Model(0x1400122a4, AMD64MicrosoftWSAStartupModel)
    # cpustate.map(wsastart)
    skip(0x1400122A4, cpustate, ret0)

    skip(0x1400122C0, cpustate, ret0)  # printf

    memset = state.models.AMD64MicrosoftZeroMemoryModel(0x140012309)
    cpustate.map(memset)

    for pc in [0x140012351, 0x14001235C]:
        skip(pc, cpustate, ret0)  # getaddrinfo

    recv = state.models.AMD64MicrosoftRecvModel(0x1400124B9)
    cpustate.map(recv)

    skip(0x1400124FF, cpustate, ret0)

    createkey = state.models.AMD64MicrosoftRegCreateKeyExAModel(0x140011DA4)
    cpustate.map(createkey)

    setvalue = state.models.AMD64MicrosoftRegSetValueExAModel(0x140011EB4)
    cpustate.map(setvalue)

    skip(0x140012540, cpustate, ret1)  # c_str

    logger.info("arranging to skip some fns")

    # for pc in [0x407eb0, 0x4069b0, 0x40f000]:
    #     skip(pc, cpustate, ret1)

    # for pc in [0x411470, 0x4115b0]:
    #     skip(pc, cpustate, ret0)

    # ------------------------------------------------------

    logger.info("set up argc/argv, and stack")

    # set up heap
    heap_address = 0x140142E00
    heap_size = 0x10000
    alloc = state.BumpAllocator(address=heap_address, size=heap_size)
    alloc.value = b"\0" * heap_size
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

    # set entry point
    cpustate.rip.value = entry
    cpustate.apply(emu)

    # tick()
    j = 0
    while True:
        j += 1

        pc = emu.read_register("pc")
        print(f"PC: {hex(pc)}")
        instr = emu.current_instruction()
        logger.info(f"emulated instr {j} {pc:x} {instr}")

        done = emu.step()

        if done:
            break
