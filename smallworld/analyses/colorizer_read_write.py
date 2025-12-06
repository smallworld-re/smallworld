import copy
import sys
import typing
import logging
from dataclasses import dataclass

from ..hinting import (
    DynamicMemoryValueHint,
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueHint,
    DynamicRegisterValueSummaryHint,
    EmulationException,
    MemoryUnavailableHint,
    MemoryUnavailableSummaryHint,
)

from ..platforms.defs.platformdef import PlatformDef, RegisterDef
from ..instructions.bsid import BSIDMemoryReferenceOperand

from . import analysis


logger = logging.getLogger(__name__)




@dataclass
class Info:
    color: int
    is_new: bool
    dynvals: typing.List[int]


@dataclass
class RegisterInfo(Info):
    register: RegisterDef

    def __str__(self: typing.Any):
        return (
            "RegisterInfo(\n"
            + f"register={self.register},\n"
            + f"color={self.color},\n"
            + f"\ndynvals={[d for d in self.dynvals]})"
        )

    def short_str(self):
        return f"{self.register.name}"

    def __hash__(self):
        return hash(
            (self.color,
             self.is_new,
             tuple(self.dynvals),
             self.register)
        )
    

@dataclass
class MemoryLvalInfo(Info):
    bsid: BSIDMemoryReferenceOperand
    size: int
    addresses: typing.List[int]

    def __str__(self: typing.Any):
        return (
            "MemoryLvalInfo(\n"
            + f"bsid={self.bsid},\n"
            + f"size={self.size},\n"
            + f"color={self.color},\n"
            + f"\ndynvals={[d for d in self.dynvals]},\n"
            + f"\naddresses={[hex(a) for a in self.addresses]})"
        )

    def short_str(self):
        return self.bsid.expr_string()

    def __hash__(self):
        return hash(
            (self.color,
             self.is_new,
             tuple(self.dynvals),
             self.bsid, self.size,
             tuple(self.addresses))
        )
    

@dataclass
class ReadInfo:
    info: Info

    def __hash__(self):
        return self.info.__hash__()

    
@dataclass
class WriteInfo:
    info: Info

    def __hash__(self):
        return self.info.__hash__()

    
@dataclass 
class DvKey:
    pc: int
    size: int
    read: bool
    new: bool
    color: typing.Optional[int]


@dataclass
class RegDvKey(DvKey):
    name: str

    def short_str(self):
        s = ""
        if self.new:
            s = "new-"
        s += self.name
        return s

    def __str__(self):
        return (f"{self.pc:x}-{self.size}-r{self.read}-n{self.new}"
                + f"-{self.short_str()}")

    def __hash__(self):
        return hash(self.__str__())

    
@dataclass
class MemLvalDvKey(DvKey):
    bsid: BSIDMemoryReferenceOperand

    def bsid_str(self):
        return self.bsid.expr_string()
        
    def short_str(self):
        s = ""
        if self.new:
            s = "new-"
        s += self.bsid_str()
        return s

    def __str__(self):
        return (f"{self.pc:x}-{self.size}-r{self.read}-n{self.new}"
                + f"-{self.short_str()}")

    def __hash__(self):
        return hash(self.__str__())


type Vector = list[float]


def dvk_info_match(dvk:DvKey, rw:typing.Union[ReadInfo,WriteInfo]):
    if type(dvk) is RegDvKey and type(rw.info) is RegisterInfo:
        if dvk.name == rw.info.register.name and dvk.new == rw.info.is_new:
            return True
    if type(dvk) is MemLvalDvKey and type(rw.info) is MemoryLvalInfo:
        if dvk.bsid == rw.info.bsid:
            return True
    return False
        

def dvk_to_info(dvk:DvKey):
    if type(dvk) is RegDvKey:
        return RegisterInfo(
            color=dvk.color,
            is_new=dvk.new,
            dynvals=[],
            register=RegisterDef(dvk.name, dvk.size)
        )
    elif type(dvk) is MemLvalDvKey:
        return MemoryLvalInfo(
            color=dvk.color,
            is_new=dvk.new,
            dynvals=[],
            bsid=dvk.bsid,
            size=dvk.size,
            addresses=[]
        )
    assert(1==0)
    

@dataclass
class WRNode:
    pc: int
    reads: typing.List[ReadInfo]
    writes: typing.List[WriteInfo]

    def __str__(self):
        return f"0x{self.pc:x} reads={self.reads} writes={self.writes}"
    
        
# src or dst in a WRGraph edge
# int is pc

# WRSrcDst = typing.NewType("WRSrcDst", typing.Tuple[int, typing.Union[ReadInfo, WriteInfo]])



@dataclass
class SrcDst:
    # src or dst in graph edge
    pc: int
    wr: typing.Union[ReadInfo, WriteInfo]

    def __hash__(self):
        return hash((self.pc, self.wr))

class WRGraph:

    def __init__(self):
        self.wr_nodes: typing.Dict[pc, WRNode] = {}
        self.in_edges:typing.Dict[SrcDst, typing.Set[SrcDst]] = {}
        self.out_edges:typing.Dict[SrcDst, typing.Set[SrcDst]] = {}

    def __find_node__(self, pc:int):
        if pc in self.wr_nodes:
            return self.wr_nodes[pc]
        return None
    
    def __get_or_create_node__(self, pc:int) -> WRNode:
        if pc in self.wr_nodes:
            return self.wr_nodes[pc]
        wr_node = WRNode(
            pc = pc,
            reads = [],
            writes = []
        )
        self.wr_nodes[pc] = wr_node
        return self.wr_nodes[pc]        

    def __get_or_add_rw_from_dvk(self, dvk:DvKey):
        node = self.__find_node__(dvk.pc)
        if dvk.read:
            for ri in node.reads:
                if dvk_info_match(dvk,ri):
                    return ri
            ri = ReadInfo(dvk_to_info(dvk))
            node.reads.append(ri)
            return ri
        else:
            for wi in node.writes:
                if dvk_info_match(dvk,wi):
                    return wi
            wi = WriteInfo(dvk_to_info(dvk))
            node.writes.append(wi)
            return wi
            
    def add_edge(self, firstobs:DvKey, read:DvKey):
        logger.info(f"add_edge {firstobs} {read}")        
        # find or create nodes
        srcnode = self.__get_or_create_node__(firstobs.pc)
        dstnode = self.__get_or_create_node__(read.pc)
        # find read/write parts of nodes or add them
        srcrwi = self.__get_or_add_rw_from_dvk(firstobs)
        dstri = self.__get_or_add_rw_from_dvk(read)
        src = SrcDst(firstobs.pc, srcrwi)
        dst = SrcDst(read.pc, dstri)
        if src not in self.out_edges:
            self.out_edges[src] = set([])
        self.out_edges[src].add(dst)
        if dst not in self.in_edges:
            self.in_edges[dst] = set([])
        self.in_edges[dst].add(src)        
        
    def derive(
            self,
            pc:int,
            is_read: bool,
            val:typing.Union[RegisterDef, BSIDMemoryReferenceOperand]
    ):
        # traverses the write-read graph following edges backwards,
        # starting with value at a pc, to identify all inputs
        print(f"derive({pc:x}, {is_read}, {val})")
        
        def der_read(n: WRNode, dst: SrcDst):
            print(f"der_read({n},{dst.wr})")
            if dst.wr.info.is_new:
                # this should be something with NO in-edges since its
                # a new read, thus an input
                assert (dst not in self.in_edges)
                return set([dst.wr.info])
            der = set([])            
            for src in self.in_edges[dst]:
                n = self.__find_node__(src.pc)
                if type(src.wr) is ReadInfo:
                    der = der | der_read(n, src)
                elif type(src.wr) is WriteInfo:
                    der = der | der_write(n, src)
            return der
            
        def der_write(n: WRNode, src: SrcDst):
            print(f"der_write({n},{src.wr}")
            # we dont have any writes in our graph that *arent* new
            assert (src.wr.info.is_new == True)
            der = set([])
            for ri in n.reads:                
                for dst in self.in_edges:
                    if dst.pc == n.pc:
                        if (type(dst.wr) is ReadInfo) and dst.wr == ri:
                            der = der | der_read(n, dst)
            return der
        
        def vmatch(val, rw):
            if ((type(val) is BSIDMemoryReferenceOperand and type(rw.info) is MemoryLvalInfo and val == rw.info.bsid)
                or
                (type(val) is RegisterDef and type(rw.info) is RegisterInfo and val.name == rw.info.register.name)):
                return True
            return False

        node = self.__find_node__(pc)
        if node is None:
            return set([])
        if is_read:
            der = set([])
            for read in node.reads:
                if vmatch(val, read):
                    for dst in self.in_edges:
                        if dst.pc == pc and (type(dst.wr) is ReadInfo) and dst.wr.info == read.info:
                            der = der | der_read(node, dst)
            return der
        else:            
            for write in node.writes:
                if vmatch(val, write):
                    for dst in self.in_edges:
                        if dst.pc == pc and (type(dst.wr) is WriteInfo) and dst.wr.info == write.info:
                            return der_write(node, dst)
            assert(1==0)

            
# this should return same key for hint regardless of actual dynamic
# value, i.e., will normalize across executions
def compute_dv_key(hint):

    def s2n(s):
        if s == "None":
            return None
        return s
    
    if type(hint) is DynamicRegisterValueHint:
        return RegDvKey(
            pc = hint.pc,
            size = hint.size,
            read = hint.use,            
            new = hint.new,
            color = None,  # not yet
            name = hint.reg_name
        )
    elif type(hint) is DynamicMemoryValueHint:
        return MemLvalDvKey(
            pc = hint.pc,
            size = hint.size,
            read = hint.use,
            new = hint.new,
            color = None,  # not yet
            bsid = BSIDMemoryReferenceOperand(
                base = s2n(hint.base),
                index = s2n(hint.index),
                scale = hint.scale,
                offset = hint.offset
            )
        )
    else:
        # should never happen
        assert (
            type(hint) is DynamicRegisterValueHint
            or type(hint) is DynamicMemoryValueHint
        )


        
class ColorizerReadWrite(analysis.Analysis):
    name = "colorizer_read_write_graph"
    description = "assemble a write->read graph from colorizer hints"
    version = "0.0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hints = {}
        self.hinter.register(DynamicRegisterValueHint, self.collect_hints)
        self.hinter.register(DynamicMemoryValueHint, self.collect_hints)
        self.max_exec_id = 0
        self.graph = WRGraph()

    def collect_hints(self, hint):
        if (
            type(hint) is DynamicRegisterValueHint
            or type(hint) is DynamicMemoryValueHint
        ):
            if hint.exec_id not in self.hints:
                self.hints[hint.exec_id] = []
            self.hints[hint.exec_id].append(hint)
            self.max_exec_id = max(hint.exec_id, self.max_exec_id)
            
    def run(self, machine):
        
        # Foreach execution,
        # collect colors (and info about their first observation),
        # establishing true cros-execution colors
        rawcolor2dvkey = {}
        dvkey2rawcolors = {}
        # this will be normalized "colors"
        dvk2num = {}
        defs = set([])
        for exec_id in range(0, self.max_exec_id+1):
            
            rawcolor2dvkey[exec_id] = {}
            dvkey2rawcolors[exec_id] = {}

            for hint in self.hints[exec_id]:
                if hint.new:
                    # a new hint means a new color; this is the first
                    # time this color was observed
                    dvk = compute_dv_key(hint)
                    if dvk not in dvk2num:
                        dvk2num[dvk] = len(dvk2num)
                    if hint.color not in rawcolor2dvkey:
                        rawcolor2dvkey[exec_id][hint.color] = dvk
                    if dvk not in dvkey2rawcolors:
                        dvkey2rawcolors[exec_id][dvk] = set([])                        
                    dvkey2rawcolors[exec_id][dvk].add(hint.color)

        # now collect "edges" which go from a newly defined color
        # (which could be a read or a write) to a use (read) of it
        edges = {}
        reads = set([])
        for exec_id in range(0, self.max_exec_id+1): 
            for hint in self.hints[exec_id]:
                if not hint.new:
                    if hint.use:
                        # A color flow, i.e. a use of a previously
                        # introduced color.                        
                        # This is where the color came from: first
                        # observation
                        # note: this could be a read or a write
                        first_obs_key = rawcolor2dvkey[hint.exec_id][hint.color]
                        true_color = dvk2num[first_obs_key]
                        assert (true_color is not None)
                        #first_obs_key.color = true_color
                        # this one *has* to be a read
                        src_key = copy.deepcopy(first_obs_key)
                        src_key.color = true_color
                        dst_key = compute_dv_key(hint)
                        dst_key.color = true_color
                        self.graph.add_edge(src_key, dst_key)
                    else:
                        # hint is a not new def ...
                        # that's just a copy right?
                        # ignore.
                        pass
                                    
        with open("col.dot", "w") as c:
            def writeln(x):
                c.write(x + '\n')                

            writeln("digraph{")
            writeln("  rankdir=LR")
            writeln("  node [shape=record];")
            
            for pc,node in self.graph.wr_nodes.items():

                def rwi_lab(n,wri):
                    i = 0
                    l = list(n.writes)
                    ls = sorted(l, key=lambda x:x.__str__())    
                    i = 0
                    for x in ls:
                        if x == wri:
                            return f"f{i}"
                        i += 1
                    l = list(n.reads)
                    ls = sorted(l, key=lambda x:x.__str__())    
                    for x in ls:
                        if x == wri:
                            return f"f{i}"
                        i += 1
                    assert (1==0)
                                                                    
                reads_str = '{'
                for r in node.reads:
                    rlab = rwi_lab(node,r)
                    pfx = "r"
                    if r.info.is_new:
                        pfx += "n"
                    reads_str += f"<{rlab}>{pfx}-{r.info.short_str()}|"
                if reads_str == '{':
                    reads_str = ''
                else:
                    reads_str = reads_str[:-1] + '}|'
                defs_str = '|{'
                for w in node.writes:
                    wlab = rwi_lab(node,w)
                    pfx = "w"
                    if w.info.is_new:
                        pfx += "n"
                    defs_str += f"<{wlab}>{pfx}-{w.info.short_str()}|"
                if defs_str == '{':
                    defs_str = ''
                else:
                    defs_str = defs_str[:-1] + '}'
                
                writeln( f'  node_{pc:x} [label="{reads_str}0x{pc:x}{defs_str}"]')

            for wsrc, rdstset in self.graph.out_edges.items():
                nsrc = self.graph.__find_node__(wsrc.pc)
                for rdst in rdstset:
                    ndst = self.graph.__find_node__(rdst.pc)
                    writeln(f"  node_{wsrc.pc:x}:{rwi_lab(nsrc,wsrc.wr)} -> node_{rdst.pc:x}:{rwi_lab(ndst,rdst.wr)}")

            writeln("}")
            
        
