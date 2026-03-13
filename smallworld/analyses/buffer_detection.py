"""Simple detection of buffer(s) as sequential read/write to elements
in an array in a loop.

Assumptions:

* One or more TraceExecution analyses ran (LoopDetection needs this)
* LoopDetection analysis ran (bc we need LoopHints)
* ColorizerSummary ran (bc we need DynamicMemoryValueSummaryHints)
* Note that ColorizerSummary means Colorizer ran. 

LoopHints are examined to discover zero or more *potential* buffer
read or writes: PBR and PBW. These are just memory load/store that
involve a pointer that is a register (or a BSID).



If there are multiple PBR or PBW that are determined to be operating
upon the same buffer (same base address and same element size) then
these are collected.


Output is a BufferDetection hint.
This contains a 

"""


def addresses_indicate_buffer(addrs):
    # Try to determine if these addresses for a ld/st for particular
    # instruction which were collected across set of traces are
    # indicative of buffer access.
    
    # note: I think addrs is a list created from a set so there should
    # not be duplicates, but this will guarantee that
    saddr = sorted(list(set(addrs)))
    saddrp = list(zip(saddr[::], saddr[1::]))
    diffs = [a-b for (a,b) in saddrp]
    if diffs[0] != 0 and len(diffs) > 2 and len(set(diffs)) == 1 and:
        # at least 3 diffs
        # and diffs between subsequent items are same
        # and they aren't all 0
        take that as a sequence of buffer accesses
        return True
    return False

    
class BufferDetection(Analysis):
    name = "buffer_detection"

    def __init__(
        self,
        *args,
        min_iter: int = 2,
        **kwargs
    ):
    super().__init__(*args, **kwargs)
    self.min_iter = min_iter
    self.loops: typing.List[LoopHint] = []
    self.traces: typing.List[TraceExecutionHint] = []
    self.mem_summs: typing.List[DynamicMemoryValueSummaryHint] = []
    self.disassembler = capstone.Cs(
        self.platdef.capstone_arch, self.platdef.capstone_mode
    )
    self.disassembler.detail = True

    def collect_traces(self, hint:Hint) -> None:
        if isinstance(hint, LoopHint):
            self.loops.append(hint)
        if isinstance(hint, TraceExecutionHint):
            self.traces.append(hint)
        if isinstance(hint, DynamicMemoryValueSummaryHint):
            self.mem_summs.append(hint)

    def get_instruction(self, machine:state.Machine, pc:int) -> capstone.CsInsn:
        for s in machine:
            if isinstance(machine, state.Memory):
                if pc >= s.address and pc < s.address + s.size:
                    code = s.read_bytes(pc, 15)
                    if code is None:
                        raise AnalysisRunError(
                            f"Unable to read instruction @ 0x{pc:x} out of machine state"                        
                        )
                    # is m.address the base of the code?
                    instructions = self.disassembler.disasm(code, s.address)
                    return (instructions[0])
        return None
        
    def run(self, machine: Machine) -> None:
        # find all the buffer read and writes that are in a loop
        pbr: typing.Set[int] = set([])
        pbw: typing.Set[int] = set([])
        for l in self.loops:
            for strand in l.strands:
                for pc in strand:
                    cs_instr = self.get_instruction(machine, pc)
                    sw_instr = Instruction.from_capstone(cs_insn)
                    assert (
                    for r in sw_instr.reads:
                        if isinstance(r, BSIDMemoryReferenceOperand):
                            pbr.add(sw_instr.address)
                    for w in sw_instr.writes:
                        if isinstance(w, BSIDMemoryReferenceOperand):
                            pbw.add(sw_instr.address)
        # Go through memory summary hints
        br: typing.Set[int] = set([])
        bw: typing.Set[int] = set([])        
        for ms in self.mem_summs:
            if ms.pc in pbr and ms.use and addresses_indicate_buffer(ms.addresses):
                # ok this is an instruction that reads and is in a
                # loop and the set of addresses seem to look like
                # sequential buffer accesses
                print(f"buffer read @ pc=0x{ms.pc}")
                br.add(pc)
            if ms.pc in pbw and (not ms.use) and addresses_indicate_buffer(ms.addresses):
                # ditto, but writes
                print(f"buffer write @ pc=0x{ms.pc}")
                bw.add(pc)

         


        
            
        
                        
