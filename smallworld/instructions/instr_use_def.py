
"""
Compute use/def sets for machine instructions using Ghidra's raw pcode,
via pyghidra.

For each machine instruction we ask Ghidra for its pcode translation and
then walk the pcode ops:

    * Each pcode op has 0..N input varnodes (reads) and 0..1 output
      varnode (write).
    * A varnode can live in one of several address spaces:
        - register : a CPU register
        - ram      : a fixed memory location (rare for raw pcode, but
                     possible — e.g. absolute loads/stores)
        - const    : an immediate; not a storage location, ignored.
        - unique   : a pcode-internal temporary that exists only inside
                     the instruction; not visible to the rest of the
                     program, so it is ignored for instruction-level
                     use/def.
        - stack    : function-local stack offsets (only appears after
                     higher-level analysis; raw pcode usually keeps
                     these as register+offset memory ops).

Instruction-level use/def, in classic gen/kill form:

    use[i] = { locations read by i before being (re)defined by i }
    def[i] = { locations written by i }

Because a single machine instruction can produce several pcode ops, an
input read after an earlier write within the same instruction would not
be a true "use" of that instruction (the read sees the value the
instruction itself produced). We mirror that by tracking what has
already been written in the current instruction and excluding it from
the use set.

Usage:
    python instr_use_def.py path/to/binary
    python instr_use_def.py path/to/binary --function main
    python instr_use_def.py path/to/binary --json out.json
"""

import argparse
import atexit
import functools
import json
import sys
import logging
import pyghidra
from enum import Enum, auto

pyghidra.start()  # boots the embedded JVM; must run before ghidra imports

from ghidra.program.model.pcode import Varnode
from ghidra.program.model.listing import Function  # noqa: E402

from smallworld.instructions import RegisterOperand
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Architecture / bytes-input plumbing for the standalone bytes-mode CLI
# --------------------------------------------------------------------------- #

# Friendly arch aliases -> Ghidra language IDs. Anything containing ':'
# is passed through verbatim, so power users can name any language id
# from Ghidra/Processors/*/data/languages/*.ldefs directly.
ARCH_ALIASES = {
    "x86":      "x86:LE:32:default",
    "x86-32":   "x86:LE:32:default",
    "i386":     "x86:LE:32:default",
    "x86-64":   "x86:LE:64:default",
    "amd64":    "x86:LE:64:default",
    "x64":      "x86:LE:64:default",
    "arm":      "ARM:LE:32:v8",
    "arm32":    "ARM:LE:32:v8",
    "armbe":    "ARM:BE:32:v8",
    "aarch64":  "AARCH64:LE:64:v8A",
    "arm64":    "AARCH64:LE:64:v8A",
    "mips":     "MIPS:BE:32:default",
    "mips32":   "MIPS:BE:32:default",
    "mipsle":   "MIPS:LE:32:default",
    "mips64":   "MIPS:BE:64:default",
    "ppc":      "PowerPC:BE:32:default",
    "ppc32":    "PowerPC:BE:32:default",
    "ppc64":    "PowerPC:BE:64:default",
    "sparc":    "sparc:BE:32:default",
    "riscv":    "RISCV:LE:64:RV64GC",
    "riscv32":  "RISCV:LE:32:RV32GC",
}


def resolve_language_id(arch):
    """Map a friendly arch name to a Ghidra LanguageID string."""
    if ":" in arch:
        return arch
    key = arch.lower()
    if key in ARCH_ALIASES:
        return ARCH_ALIASES[key]
    raise SystemExit(
        f"unknown architecture {arch!r}; pass a full Ghidra language id "
        f"like 'x86:LE:64:default' or one of: "
        f"{', '.join(sorted(ARCH_ALIASES))}"
    )


def parse_bytes_arg(spec):
    """Decode a CLI bytes spec into raw bytes.

    Accepts:
      * a hex string ('deadbeef', '0xdead beef', 'de,ad,be,ef')
      * '@path' to read raw binary bytes from a file
      * '-' to read raw binary bytes from stdin
    """
    if spec == "-":
        return sys.stdin.buffer.read()
    if spec.startswith("@"):
        with open(spec[1:], "rb") as f:
            return f.read()
    cleaned = spec.replace(" ", "").replace("\n", "").replace(",", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise SystemExit("hex bytes must have an even number of hex digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SystemExit(f"invalid hex bytes: {exc}") from exc


def _varnode_operand(program, vn):
    
    # returning None seems to signal that this is neither a Reg nor memory.
    if vn is None:
        return None
    if vn.isConstant():
        return None
    if vn.isUnique():
        return None

    if vn.isRegister():
        reg = program.getRegister(vn.getAddress(), vn.getSize())
        assert (reg is not None)
        # Normalize to the canonical (largest) register name if you
        # prefer; here we keep the size-specific name (e.g. "EAX"
        # vs "RAX") because that's what the instruction actually
        # touches.
        return RegisterOperand(reg.getName().lower())

    
    # has to be true -- a concrete address
    assert vn.isAddress()
    addr = vn.getAddress()
    space = addr.getAddressSpace().getName()
    assert space == "ram"
    # dont we want this to return size too?  Do we even have that?
    return BSIDMemoryReferenceOperand(
        segment=None,
        base=None,
        index=None,
        scale=1,
        offset=addr.getOffset(),
        size=0 # its just an address
    )            



def _unique_key(vn):
    """Hashable key for a unique-space varnode."""
    return (int(vn.getAddress().getOffset()), int(vn.getSize()))


# --------------------------------------------------------------------------- #
# Symbolic-expression machinery for STORE/LOAD addresses
# --------------------------------------------------------------------------- #
#
# Within a single machine instruction we trace data flow through pcode
# 'unique' temporaries so that when we hit a STORE/LOAD we can render
# the memory address symbolically — e.g. for PPC's
#
#     stwu r1, -0x30(r1)
#
# we want to emit a def of  ram[(r1 + -0x30):4]  rather than just
# noting "memory got written somewhere". The trick is that the address
# was computed in a unique by an earlier INT_ADD; we store that
# unique's expression as a string keyed by its (offset, size) and
# substitute it back when the STORE consumes it.

class _PCODE_OP(Enum):
    COPY = auto()           
    LOAD = auto()           
    STORE = auto()          
    BRANCH = auto()         
    CBRANCH = auto()        
    BRANCHIND = auto()      
    CALL = auto()           
    CALLIND = auto()        
    RETURN = auto()
    PIECE = auto()          
    SUBPIECE = auto()       
    INT_EQUAL = auto()      
    INT_NOTEQUAL = auto()   
    INT_LESS = auto()       
    INT_SLESS = auto()      
    INT_LESSEQUAL = auto()  
    INT_SLESSEQUAL = auto() 
    INT_ZEXT = auto()       
    INT_SEXT = auto()       
    INT_ADD = auto()        
    INT_SUB = auto()        
    INT_CARRY = auto()      
    INT_SCARRY = auto()     
    INT_SBORROW = auto()    
    INT_2COMP = auto()      
    INT_NEGATE = auto()     
    INT_XOR = auto()        
    INT_AND = auto()        
    INT_OR = auto()         
    INT_LEFT = auto()       
    INT_RIGHT = auto()      
    INT_SRIGHT = auto()     
    INT_MULT = auto()       
    INT_DIV = auto()        
    INT_REM = auto()        
    INT_SDIV = auto()       
    INT_SREM = auto()       
    BOOL_NEGATE = auto()    
    BOOL_XOR = auto()       
    BOOL_AND = auto()       
    BOOL_OR = auto()        
    FLOAT_EQUAL = auto()    
    FLOAT_NOTEQUAL = auto() 
    FLOAT_LESS = auto()     
    FLOAT_LESSEQUAL = auto()
    FLOAT_ADD = auto()      
    FLOAT_SUB = auto()      
    FLOAT_MULT = auto()     
    FLOAT_DIV = auto()      
    FLOAT_NEG = auto()      
    FLOAT_ABS = auto()      
    FLOAT_SQRT = auto()     
    FLOAT_CEIL = auto()     
    FLOAT_FLOOR = auto()    
    FLOAT_ROUND = auto()    
    FLOAT_NAN = auto()      
    INT2FLOAT = auto()      
    FLOAT2FLOAT = auto()    
    TRUNC = auto()          

    
     
_PCODE_OP_INFO = { 
    _PCODE_OP.COPY:             ("<-", [0], True),
    _PCODE_OP.LOAD:             ("<m-", [1], True),
    _PCODE_OP.STORE:            ("-m>", [1], True),
    _PCODE_OP.BRANCH:           ("b", [], False),         # input is conc addr only
    _PCODE_OP.CBRANCH:          ("cb", [1], False),       # the condition
    _PCODE_OP.BRANCHIND:        ("bi", [0], False),       # the dynamically determined target
    _PCODE_OP.CALL:             None,                     # exception
    _PCODE_OP.CALLIND:          None,                     # exception
    _PCODE_OP.RETURN:           None,                     # exception
    _PCODE_OP.PIECE:            ("p", [0, 1], True),    
    _PCODE_OP.SUBPIECE:         ("s", [0], True),
    _PCODE_OP.INT_EQUAL:        ("==", [0, 1], True),
    _PCODE_OP.INT_NOTEQUAL:     ("!=", [0, 1], True),
    _PCODE_OP.INT_LESS:         ("<u", [0, 1], True),
    _PCODE_OP.INT_SLESS:        ("<s", [0, 1], True),
    _PCODE_OP.INT_LESSEQUAL:    ("<=u", [0, 1], True),
    _PCODE_OP.INT_SLESSEQUAL:   ("<=u", [0, 1], True),
    _PCODE_OP.INT_ZEXT:         ("zx", [0], True),
    _PCODE_OP.INT_SEXT:         ("sx", [0], True),    
    _PCODE_OP.INT_ADD:          ("+", [0, 1], True),
    _PCODE_OP.INT_SUB:          ("-", [0, 1], True),
    _PCODE_OP.INT_CARRY:        ("c", [0, 1], True),
    _PCODE_OP.INT_SCARRY:       ("sc", [0, 1], True),
    _PCODE_OP.INT_SBORROW:      ("sb", [0, 1], True),
    _PCODE_OP.INT_2COMP:        ("-", [0], True),
    _PCODE_OP.INT_NEGATE:       ("~", [0], True),    
    _PCODE_OP.INT_XOR:          ("^", [0, 1], True),
    _PCODE_OP.INT_AND:          ("&", [0, 1], True),
    _PCODE_OP.INT_OR:           ("|", [0, 1], True),
    _PCODE_OP.INT_LEFT:         ("<<", [0, 1], True),
    _PCODE_OP.INT_RIGHT:        (">>", [0, 1], True),
    _PCODE_OP.INT_SRIGHT:       (">>s", [0, 1], True),                
    _PCODE_OP.INT_MULT:         ("*", [0, 1], True),                
    _PCODE_OP.INT_DIV:          ("/", [0, 1], True),                
    _PCODE_OP.INT_REM:          ("%", [0, 1], True),                
    _PCODE_OP.INT_SDIV:         ("/s", [0, 1], True),                
    _PCODE_OP.INT_SREM:         ("%s", [0, 1], True),                
    _PCODE_OP.BOOL_NEGATE:      ("~", [0], True),    
    _PCODE_OP.BOOL_XOR:         ("^", [0, 1], True),
    _PCODE_OP.BOOL_AND:         ("&", [0, 1], True),
    _PCODE_OP.BOOL_OR:          ("|", [0, 1], True),
    _PCODE_OP.FLOAT_EQUAL:      ("==f", [0, 1], True),
    _PCODE_OP.FLOAT_NOTEQUAL:   ("!=f", [0, 1], True),
    _PCODE_OP.FLOAT_LESS:       ("<f", [0, 1], True),
    _PCODE_OP.FLOAT_LESSEQUAL:  ("<=f", [0, 1], True),
    _PCODE_OP.FLOAT_ADD:        ("+f", [0, 1], True),
    _PCODE_OP.FLOAT_SUB:        ("-f", [0, 1], True),
    _PCODE_OP.FLOAT_MULT:       ("*f", [0, 1], True),                
    _PCODE_OP.FLOAT_DIV:        ("*/", [0, 1], True),                
    _PCODE_OP.FLOAT_NEG:        ("-", [0], True),
    _PCODE_OP.FLOAT_ABS:        ("!", [0], True),
    _PCODE_OP.FLOAT_SQRT:       ("r", [0], True),        
    _PCODE_OP.FLOAT_CEIL:       ("cf", [0], True),
    _PCODE_OP.FLOAT_FLOOR:      ("f", [0], True),    
    _PCODE_OP.FLOAT_ROUND:      ("r", [0], True),
    _PCODE_OP.FLOAT_NAN:        ("n", [0], True),    
    _PCODE_OP.INT2FLOAT:        ("i2f", [0], True),
    _PCODE_OP.FLOAT2FLOAT:      ("f2f", [0], True),
    _PCODE_OP.TRUNC:            ("t", [0], True)
    }




def _format_const(val, size_bytes):
    """Render a constant signed (with a '-' sign) when its high bit is
    set, otherwise as an unsigned hex literal. Makes addresses like
    '0xffffffd0' read as the more natural '-0x30'."""
    val = int(val)
    if val == 0:
        return "0"
    if size_bytes <= 0 or size_bytes >= 8:
        return f"0x{val:x}"
    width = size_bytes * 8
    sign_bit = 1 << (width - 1)
    if val & sign_bit:
        signed = val - (1 << width)
        return f"-0x{-signed:x}"
    return f"0x{val:x}"


# def _vn_expr(vn, program, unique_exprs, register_exprs):
#     """Stringify a varnode as a symbolic expression.

#     Registers that have already been written earlier in this
#     instruction render as their tracked expression rather than as
#     their plain name, so 'STORE ram, RSP, ...' after 'RSP = RSP - 8'
#     prints the address as '(RSP - 0x8)', not 'RSP'.

# really this should return one of the following
# * Int
# * expr for a uniq, in terms of input quantities
# * expr for a register at this point in seq, in terms of input quantities
# note: i uniq and key isnt there, we return a default STRING

# vn can be a constant, an address, a uniq or a register.# first two are easy -- return an int of some kind? 
# last two are rendered in terms of input quantities to the op sequence
def _vn_expr(vn, program, unique_exprs, register_exprs):

    assert (vn is not None)

    if isinstance(vn, Varnode):
     
        if vn.isConstant():
            val = int(vn.getOffset())
            width = vn.getSize() * 8
            sign_bit = 1 << (width - 1)
            if val & sign_bit:
                return val - (1<<width)
            return int(vn.getOffset())
        if vn.isUnique():
            key = _unique_key(vn)
            assert(key in unique_exprs)
            return unique_exprs[key]
            # return unique_exprs.get(key, f"$U{key[0]:x}")
        # i guess this could be a reg or an address?
        operand = _varnode_operand(program, vn)
        if operand is not None:
            # this means its either a Reg or Memory
            if vn.isRegister():
                if operand in register_exprs:
                    # re-express that reg in terms of inputs?
                    return register_exprs[operand]
            # ok to return 
            return operand                       
        operand = vn.getAddress()

    else:
        # maybe we are never here?
        breakpoint()
        assert isinstance(vn, list)
        assert(len(vn) >= 2)
        assert(len(vn) <= 3)
        assert isinstance(vn[0], str)
        name = vn[0]
        if len(vn) == 2:
            return [name, _vn_expr(vn[1], program, unique_exprs, register_exprs)]
        return [name,
                _vn_expr(vn[1], program, unique_exprs, register_exprs),
                _vn_expr(vn[2], program, unique_exprs, register_exprs)]        
        
        
def _op_expr(op, program, unique_exprs, register_exprs):
    mnemonic_ind = _PCODE_OP[op.getMnemonic()]
    (lab, inp_inds, outp) = _PCODE_OP_INFO[mnemonic_ind]
    le = [mnemonic_ind]
    inputs = op.getInputs()
    for ind in inp_inds:
        vne = _vn_expr(inputs[ind], program, unique_exprs, register_exprs)
        le.append(vne)
    return le


def _space_name(program, space_id_vn):
    """STORE/LOAD encode the destination address space in input[0],
    which is a 'constant' varnode whose value is the space id."""
    space_id = int(space_id_vn.getOffset())
    space = program.getAddressFactory().getAddressSpace(space_id)
    return space.getName() if space is not None else f"space{space_id}"


def _addr_expr_to_mem_ref_op(addr_expr, size):
    if (len(addr_expr) != 3):
        breakpoint()
    assert (len(addr_expr) == 3)
    (op, a1, a2) = addr_expr
    assert type(a1) is RegisterOperand and type(a2) is int
    assert op == "INT_ADD"
    # assume that is the base
    return BSIDMemoryReferenceOperand(
        segment=None,
        base=a1.name,
        index=None,
        scale=1,
        offset=a2,
        size=size)


# resolve this input using sstate
# recurse if you need to.
# returns either
# * register if that's not yet in sstate (not yet assigned)
# * s-expr for unique
def resolve_input(inp, sstate):
        
    if isinstance(inp, tuple):
        (mnem, rhs_inps) = inp
        r_rhs_inps = []
        for i in rhs_inps:
            r_rhs_inps.append(resolve_input(i, sstate))
        return (mnem, r_rhs_inps)
    else:
        if inp.isUnique():
            ik = _unique_key(inp)
            # this better be in sstate
            assert (ik in sstate)
            return sstate[ik]
        elif inp.isRegister():
            if not (inp in sstate):
                # register not yet assigned in this chain of pcode
                return inp
            breakpoint()
            (mnem, rhs_inp) = sstate[inp]
            # register has been assigned and this was the computation
            if mnem == _PCODE_OP.COPY_PC:
                return rhs_inp[0]
            return sstate[inp]            
    # addr or const?
    return inp
    
def update_symstate(op, sstate):
    # resolve all inputs (args) to this op in terms of
    # inputs-to-the-instruction, and then record
    # mapping from out to that resolution
    ris = []
    for inp in op.getInputs():
        ris.append(resolve_input(inp, sstate))    
    # special case! There's no need for an s-expr. This is basically
    # just an assignment
    mnemonic = _PCODE_OP[op.getMnemonic()]
    if mnemonic == _PCODE_OP.COPY:
        assert (len(ris)) == 1
        val = ris[0]
    else:
        val = (mnemonic, ris)
    outp = op.getOutput()
    if outp is None:
        # ditch it; could be a store?
        return
    assert (outp.isUnique() or outp.isRegister())    
    if outp.isUnique():
        ok = _unique_key(outp)
        sstate[ok] = val
    elif outp.isRegister():
        sstate[outp] = val

        
def uniq2bsid(u, sstate, program, size):
    assert u.isUnique()
    k = _unique_key(u)
    assert (k in sstate)
    res = sstate[k]
    if isinstance(res, tuple):
        (mnemonic, args) = res
        if mnemonic == _PCODE_OP.INT_ADD:
            if args[0].isRegister() and args[1].isConstant():
                reg = program.getRegister(args[0])
                return BSIDMemoryReferenceOperand(
                    segment=None,
                    base = reg.name,
                    index = None,
                    offset = args[1].getOffset(),
                    size = size
                )
    raise Exception(f"unexpected sstate: {res}")
        

# --------------------------------------------------------------------------- #
# Per-instruction use/def
# --------------------------------------------------------------------------- #

def instruction_use_def(program, instr):
    """Return (use_set, def_set) for a single machine instruction.

    The sets are strings:
      * registers  — e.g. 'r1', 'RAX', 'CF'
      * memory locations — e.g. 'ram[(r1 + -0x30):4]', meaning a
        4-byte cell in the 'ram' address space at the symbolic
        address '(r1 + -0x30)'. The address expression is rendered
        algebraically over the registers and constants that
        contributed to it within this instruction.

    Memory defs come from STORE pcode ops; memory uses come from LOAD
    pcode ops. Register defs come from non-STORE pcode ops whose
    output varnode is in the register space. We trace data flow
    through 'unique' varnodes so the memory address expression names
    the original registers, not the pcode temporaries.
    """
    uses = set()
    defs = set()
    written_so_far = set() # registers written so far 
    unique_exprs = {}    # (offset, size) -> expression-string for pcode temps
    register_exprs = {}  # register-name   -> expression-string after a write

    sstate = {}
    pdebug = True

    for op in instr.getPcode():

        if pdebug:
            logger.info(f"pcode = {op}")

        try:
            update_symstate(op, sstate)
        except Exception as e:
            print(f"update_symstate seems to have had a problem {e}")
            assert(1==0)
                    
        mnemonic = _PCODE_OP[op.getMnemonic()]
        
        if pdebug:
            for i, inp in enumerate(op.getInputs()):
                logger.info(f"input {i} {inp} {_varnode_operand(program, inp)}")
            logger.info(f"output {op.getOutput()} {_varnode_operand(program, op.getOutput())}")

        # This is blacklisting some odd PPCisms
        if mnemonic == _PCODE_OP.COPY:
            input0 = _varnode_operand(program, op.getInput(0))
            output = _varnode_operand(program, op.getOutput())
            # ghidra hallucinates a full-fledged register called `r2Save`
            # in which case we bail since this copy isn't real
            if input0 and isinstance(input0, RegisterOperand):
                if input0.name == "r2Save" and output.name == "r2":
                    continue
            if output and isinstance(output, RegisterOperand):
                if output.name == "r2Save" and input0.name == "r2":
                    continue
                
        # ---- collect register reads from this op's inputs ------------ #
        for inp in op.getInputs():            
            if inp.isRegister():
                reg = _varnode_operand(program, inp)
                assert isinstance(reg, RegisterOperand)                
                assert not (reg is None)
                if reg in written_so_far:
                    continue
                if pdebug:
                    logger.info(f"1 use {reg}")
                uses.add(reg)

        # ---- STORE: emit a symbolic memory def ----------------------- #
        if mnemonic == _PCODE_OP.STORE:
            inputs = op.getInputs()
            # logger.info(f"store {len(inputs)} inputs")
            assert len(inputs) == 3
            space = _space_name(program, inputs[0])
            assert (space == "ram")

            if inputs[1].isUnique():
                mem = uniq2bsid(inputs[1], sstate, program, inputs[2].size)                
            else:
                breakpoint()
                raise Exception(f"store with address not a unique?")
                
            if pdebug:
                logger.info(f"2 def mem {mem}")
            defs.add(mem)
            continue  # STORE has no output varnode

        # ---- LOAD: emit a symbolic memory use, propagate value ------- #
        if mnemonic == _PCODE_OP.LOAD:
            inputs = op.getInputs()
            # logger.info(f"load {len(inputs)} inputs")
            assert len(inputs) == 2
            out = op.getOutput()    # reg
            assert not (out is None)
            space = _space_name(program, inputs[0])
            assert (space == "ram")
            # this should really get us a bsid for the address
            # inputs[1] is the ptr

            if inputs[1].isUnique():
                mem = uniq2bsid(inputs[1], sstate, program, op.getOutput().size)
            else:
                raise Exception(f"load with address not a unique?")
            
            # why would mem be in defs... If we had previously stored to this in this op sequence?
            if not (mem in defs):
                if pdebug:
                    logger.info(f"3 use mem {mem}")
                uses.add(mem)
            if out.isUnique():
                # remember that this unique is really this mem load
                unique_exprs[_unique_key(out)] = mem
            else:
                reg = _varnode_operand(program, out)
                assert not (reg is None)
                assert isinstance(reg, RegisterOperand)
                if pdebug:
                    logger.info(f"4 def operand {reg}")
                defs.add(reg)
                written_so_far.add(reg)
                # remember that this register, which has been written,
                # is really this loaded value
                register_exprs[reg] = mem
            continue

        # ---- non-STORE/LOAD output handling -------------------------- #
        out = op.getOutput()
        if out is None:
            continue
        if out.isUnique():
            continue
        assert out.isRegister()
        reg = _varnode_operand(program, out)
        assert not ("Save" in reg.name)
        if pdebug:
            logger.info(f"5 def reg {reg}")
        defs.add(reg)
        written_so_far.add(reg)

    return uses, defs


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def iter_instructions(program, function_name=None):
    listing = program.getListing()
    if function_name is None:
        yield from listing.getInstructions(True)
        return

    fm = program.getFunctionManager()
    fn: Function | None = None
    for f in fm.getFunctions(True):
        if f.getName() == function_name:
            fn = f
            break
    if fn is None:
        raise SystemExit(f"function {function_name!r} not found")
    body = fn.getBody()
    yield from listing.getInstructions(body, True)


def analyze(binary_path, function_name=None, project_dir=None,
            project_name="usedef-proj"):
    results = []
    with pyghidra.open_program(
        binary_path,
        project_location=project_dir,
        project_name=project_name,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        for instr in iter_instructions(program, function_name):
            uses, defs = instruction_use_def(program, instr)
            results.append({
                "address": str(instr.getAddress()),
                "instr": instr.toString(),
                "use": sorted(uses),
                "def": sorted(defs),
            })
    return results


# --------------------------------------------------------------------------- #
# Long-lived program cache (one open Ghidra program per architecture)
# --------------------------------------------------------------------------- #
#
# Spinning up a fresh Ghidra project + BinaryLoader pipeline costs ~150-350 ms
# per call; the actual disassembly + use/def of a 4-byte instruction is sub-ms.
# To amortize the setup cost across many cold-path calls (cache misses on the
# result lru_cache above), we keep one `pyghidra.open_program` context alive
# per architecture and repopulate its single memory block on each call. We
# bypass the context manager's __exit__ for the lifetime of the process and
# rely on an atexit hook for graceful teardown.

_program_cache = {}  # language_id (str) -> (open_program-cm, flat_api, addr_space)


def _get_or_create_program(arch):
    """Return (flat_api, program, addr_space) for a long-lived program
    of the given architecture, creating it on the first call."""
    lang_id = resolve_language_id(arch)
    entry = _program_cache.get(lang_id)
    if entry is not None:
        cm, flat_api, space = entry
        return flat_api, flat_api.getCurrentProgram(), space

    # First time we've seen this arch: open a fresh program around a
    # one-byte placeholder file. We manually __enter__ the context and
    # stash it; teardown happens at atexit (or on eviction after error).
    import os
    import tempfile

    fd, placeholder = tempfile.mkstemp(suffix=".bin", prefix="usedef-init-")
    try:
        os.write(fd, b"\x00")
        os.close(fd)
        cm = pyghidra.open_program(
            placeholder,
            language=lang_id,
            loader="ghidra.app.util.opinion.BinaryLoader",
            analyze=False,
        )
        flat_api = cm.__enter__()
    finally:
        try:
            os.unlink(placeholder)
        except OSError:
            pass

    program = flat_api.getCurrentProgram()
    # Capture the address space BinaryLoader used so per-call blocks
    # land in the same space (rather than guessing at default-space
    # semantics, which can differ between languages).
    initialized = [b for b in program.getMemory().getBlocks() if b.isInitialized()]
    if not initialized:
        cm.__exit__(None, None, None)
        raise RuntimeError(
            f"BinaryLoader produced no initialized blocks for {lang_id!r}"
        )
    space = initialized[0].getStart().getAddressSpace()

    _program_cache[lang_id] = (cm, flat_api, space)
    return flat_api, program, space


def _evict_program(arch):
    """Drop a cached program — used after an error left it in a bad
    state, or proactively before process exit."""
    try:
        lang_id = resolve_language_id(arch)
    except SystemExit:
        # If arch is no longer resolvable (shouldn't happen normally),
        # fall through to a no-op rather than blowing up cleanup.
        return
    entry = _program_cache.pop(lang_id, None)
    if entry is None:
        return
    cm, _flat_api, _space = entry
    try:
        cm.__exit__(None, None, None)
    except Exception:
        # Best-effort teardown; the JVM may already be torn down.
        pass


@atexit.register
def _shutdown_program_cache():
    for lang_id in list(_program_cache):
        entry = _program_cache.pop(lang_id, None)
        if entry is None:
            continue
        cm, _, _ = entry
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass


def _populate_program(program, addr_space, byte_data, base_address):
    """Swap whatever bytes are currently loaded for `byte_data` at
    `base_address`, then disassemble the new range."""
    from ghidra.program.model.address import AddressSet
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.util.task import TaskMonitor
    from java.io import ByteArrayInputStream
    import jpype

    memory = program.getMemory()
    listing = program.getListing()

    tx = program.startTransaction("usedef-repopulate")
    try:
        # 1. Wipe everything. Clear code units first so removeBlock has
        #    nothing to complain about, then drop the block.
        for block in list(memory.getBlocks()):
            try:
                listing.clearCodeUnits(block.getStart(), block.getEnd(), False)
            except Exception:
                # Non-fatal: removeBlock will still handle it for typical
                # raw-binary blocks.
                pass
            memory.removeBlock(block, TaskMonitor.DUMMY)

        # 2. Create a fresh initialized block holding the new bytes at
        #    the requested base, in the same address space BinaryLoader
        #    originally chose.
        addr = addr_space.getAddress(int(base_address))
        # Java bytes are signed (-128..127); convert 0..255 explicitly so
        # jpype doesn't choke on values above 0x7f.
        signed = [(b - 256 if b >= 128 else b) for b in byte_data]
        jbytes = jpype.JArray(jpype.JByte)(signed)
        stream = ByteArrayInputStream(jbytes)
        memory.createInitializedBlock(
            "code", addr, stream, len(byte_data),
            TaskMonitor.DUMMY, False,
        )

        # 3. Disassemble the full range of the new block.
        block = memory.getBlock(addr)
        addr_set = AddressSet(block.getStart(), block.getEnd())
        DisassembleCommand(addr_set, addr_set, True).applyTo(
            program, TaskMonitor.DUMMY,
        )
    finally:
        program.endTransaction(tx, True)


def _analyze_bytes_inner(byte_data, arch, base_address):
    """Uncached implementation; see analyze_bytes for the public API.

    Reuses a long-lived Ghidra program per architecture rather than
    tearing it down between calls. On any error we evict the cached
    program so a subsequent call rebuilds it cleanly rather than
    inheriting a half-initialized state.
    """
    try:
        flat_api, program, addr_space = _get_or_create_program(arch)
        _populate_program(program, addr_space, byte_data, base_address)

        results = []
        for instr in program.getListing().getInstructions(True):
            uses, defs = instruction_use_def(program, instr)
            results.append({
                "address": str(instr.getAddress()),
                "instr":   instr.toString(),
                # "use":     sorted(uses),
                # "def":     sorted(defs),
                "use":     uses,
                "def":     defs,
            })
        return results
    except Exception:
        _evict_program(arch)
        raise


# --------------------------------------------------------------------------- #
# Cached front-door for analyze_bytes
# --------------------------------------------------------------------------- #
#
# Each uncached call spins up a Ghidra project, runs BinaryLoader, and
# disassembles -- on the order of seconds. For interactive use where the
# same byte string and arch get analyzed repeatedly (REPL, test loops,
# notebooks), we memoize the result so cache hits cost ~microseconds.
#
# The cache stores an *immutable* frozen form (tuple of tuples) so a
# caller mutating their returned list doesn't corrupt cached state on
# the next hit. The public `analyze_bytes` thaws the frozen form back
# into the list-of-dicts shape the rest of the code expects.

_DEFAULT_CACHE_SIZE = 4096


@functools.lru_cache(maxsize=_DEFAULT_CACHE_SIZE)
def _analyze_bytes_cached(byte_data: bytes, arch: str, base_address: int):
    """Hashable wrapper around _analyze_bytes_inner; returns a frozen
    tuple-of-tuples so callers can't accidentally mutate cached state."""
    raw = _analyze_bytes_inner(byte_data, arch, base_address)
    return tuple(
        (r["address"], r["instr"], tuple(r["use"]), tuple(r["def"]))
        for r in raw
    )


def analyze_bytes(byte_data, arch, base_address=0):
    """Disassemble a raw byte buffer with the given architecture and
    return per-instruction use/def.

    Caching is layered for speed:

      * Result cache (lru_cache, size 4096): exact-input repeats are
        served from a hashtable in microseconds. Use
        `analyze_bytes.cache_clear()` to drop the cache and
        `analyze_bytes.cache_info()` to inspect it.

      * Program reuse: per architecture, we hold one Ghidra program
        open for the lifetime of the process and reload its memory
        block on each cold-path call instead of spinning up a fresh
        project. The first call per architecture pays the one-time
        SLEIGH / BinaryLoader cost (~200 ms to ~2 s depending on the
        ISA); subsequent calls swap bytes through `Memory.removeBlock`
        / `createInitializedBlock` in ~1 ms. Cached programs are torn
        down by an atexit hook; if an analysis errors out, the
        affected program is evicted so the next call rebuilds it.
    """
    # Normalize byte_data so memoryview/bytearray callers also hit the cache
    if not isinstance(byte_data, bytes):
        byte_data = bytes(byte_data)
    cached = _analyze_bytes_cached(byte_data, arch, int(base_address))
    # Thaw back to the mutable list-of-dicts the rest of the script
    # expects. This is cheap (O(n) over instructions) and prevents
    # callers from mutating the cached representation.
    return [
        {"address": a, "instr": i, "use": list(u), "def": list(d)}
        for (a, i, u, d) in cached
    ]


# Expose the lru_cache control surface on the public function so callers
# don't have to know the underscore-prefixed name exists.
analyze_bytes.cache_clear = _analyze_bytes_cached.cache_clear
analyze_bytes.cache_info = _analyze_bytes_cached.cache_info


def _emit_results(results, json_path):
    if json_path:
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"wrote {len(results)} instructions to {json_path}",
              file=sys.stderr)
        return
    for r in results:
        logger.info(f"{r['address']:>14}  {r['instr']}")
        logger.info(f"                use = {{{', '.join(r['use'])}}}")
        logger.info(f"                def = {{{', '.join(r['def'])}}}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Per-instruction use/def via pyghidra. Two modes: "
                    "analyze a binary on disk, or analyze a raw byte "
                    "buffer plus an architecture string.",
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    # ---- file mode ------------------------------------------------------- #
    p_file = sub.add_parser("file", help="analyze a binary file on disk")
    p_file.add_argument("binary", help="path to the binary to analyze")
    p_file.add_argument("--function", default=None,
                        help="restrict to a single function by name")
    p_file.add_argument("--project-dir", default=None,
                        help="Ghidra project directory (default: temp)")
    p_file.add_argument("--json", default=None,
                        help="write results to this JSON file instead of stdout")

    # ---- bytes mode ------------------------------------------------------ #
    p_bytes = sub.add_parser(
        "bytes",
        help="analyze a raw byte buffer plus an architecture",
        description=(
            "Disassemble raw machine-code bytes with the given "
            "architecture and emit per-instruction use/def. The bytes "
            "input accepts a hex string ('deadbeef'), '@path' to read "
            "raw bytes from a file, or '-' to read raw bytes from stdin."
        ),
    )
    p_bytes.add_argument(
        "--arch", required=True,
        help="architecture: a full Ghidra language id "
             "('x86:LE:64:default') or an alias "
             "(x86-64, arm64, mips, ppc, riscv, ...).",
    )
    p_bytes.add_argument(
        "--bytes", dest="byte_spec", required=True,
        help="hex string, @path/to/file, or - for stdin",
    )
    p_bytes.add_argument(
        "--base", default="0",
        help="base address for the byte buffer (default: 0). "
             "Hex like 0x1000 is accepted.",
    )
    p_bytes.add_argument(
        "--json", default=None,
        help="write results to this JSON file instead of stdout",
    )

    args = ap.parse_args(argv)

    if args.mode == "file":
        results = analyze(
            args.binary,
            function_name=args.function,
            project_dir=args.project_dir,
        )
    elif args.mode == "bytes":
        byte_data = parse_bytes_arg(args.byte_spec)
        if not byte_data:
            raise SystemExit("no bytes to analyze")
        base = int(args.base, 0)
        results = analyze_bytes(byte_data, args.arch, base_address=base)
    else:  # pragma: no cover
        ap.error("unknown mode")

    _emit_results(results, args.json)


if __name__ == "__main__":
    main()
