import logging
import typing

import networkx as nx
from dataclass import dataclass

from .. import hinting
from ..instructions.bsid import BSIDMemoryReferenceOperand
from ..platforms.defs.platformdef import PlatformDef, RegisterDef
from . import analysis

logger = logging.getLogger(__name__)


"""Nodes in this graph are either instructions or colors.

* instruction, in which case it is an integer, the program counter of
  the instruction

* color node, which represents the introduction of a color or new
  value. These are not integers. They need to represent the source of
  an input to the trace which can be:

** initial register value, in which case we need its name
** some memory lval
*** size
*** start address (or maybe this is addresses? since it may have
    been a source of multiple colors.
*** pc of instruction that did the read <-- really just for human debugging
*** bsid or concrete address for read   <-- ditto

Out-edges for a node represent something being defined by that node.
In-edges for a node represent uses of values by that node.

"""


class DefUseGraph(nx.MultiDiGraph):
    def add_def_use(self, def_node, use_node, def_info, use_info, color):
        self.add_edge(
            def_node,
            use_node,
            {"def_info": def_info, "use_info": use_info, "color": color},
        )


##################################
#
# nodes


@dataclass
class DefUseNode:
    pc: int


@dataclass
class InstructionNode(DefUseNode):
    pass

    def __str__(self: typing.Any):
        return f"InstructionNode(pc={self.pc:x}"


@dataclass
class ColorNode(DefUseNode):
    color: int

    def __str__(self: typing.Any):
        return f"ColorNode(pc={self.pc:x},color={self.color}"


@dataclass
class Info:
    color: int
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


@dataclass
class UseInfo:
    info: Info


@dataclass
class DefInfo:
    info: Info


class ColorizerDefUse(analysis.Analysis):
    name = "colorizer_def_use_graph"
    description = "assemble a def use graph from colorizer summary hints"
    version = "0.0.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.new_hints = []
        self.not_new_hints = []
        self.hinter.register(
            hinting.DynamicRegisterValueSummaryHint, self.collect_hints
        )
        self.hinter.register(hinting.DynamicMemoryValueSummaryHint, self.collect_hints)

    def collect_hints(self, hint: hinting.Hint):
        if (
            type(hint) is hinting.DynamicRegisterValueSummaryHint
            or type(hint) is hinting.DynamicMemoryValueSummaryHint
        ):
            if hint.new:
                self.new_hints.append(hint)
            else:
                self.not_new_hints.append(hint)

    def run(self, machine):
        self.du_graph = DefUseGraph()
        color2genesis = {}

        platform = machine.get_platform()
        pdef = PlatformDef.for_platform(platform)

        def hint_def_use_info(hint):
            if hint.use:
                if type(hint) is hinting.DynamicRegisterValueSummaryHint:
                    return UseInfo(
                        RegisterInfo(
                            register=pdef.registers[hint.reg_name],
                            color=hint.color,
                            dynvals=hint.dynamic_values,
                        )
                    )
                if type(hint) is hinting.DynamicMemoryValueSummaryHint:
                    return UseInfo(
                        MemoryLvalInfo(
                            bsid=BSIDMemoryReferenceOperand(
                                hint.base, hint.index, hint.scale, hint.offset
                            ),
                            size=hint.size,
                            color=hint.color,
                            dynvals=hint.dynamic_values,
                            addresses=hint.addresses,
                        )
                    )
            else:
                if type(hint) is hinting.DynamicRegisterValueSummaryHint:
                    return DefInfo(
                        RegisterInfo(
                            register=pdef.registers[hint.reg_name],
                            color=hint.color,
                            dynvals=hint.dynamic_values,
                        )
                    )
                if type(hint) is hinting.DynamicMemoryValueSummaryHint:
                    return DefInfo(
                        MemoryLvalInfo(
                            bsid=BSIDMemoryReferenceOperand(
                                hint.base, hint.index, hint.scale, hint.offset
                            ),
                            size=hint.size,
                            color=hint.color,
                            dynvals=hint.dynamic_values,
                            addresses=hint.addresses,
                        )
                    )

        for hint in self.new_hints:
            # this is a new color so its either an input or a write of
            # a computed value

            # some sanity checking
            assert "def" in hint.message
            assert hint.color not in color2genesis
            assert (hint.use and ("read" in hint.message)) or (
                (not hint.use) and ("write" in hint.message)
            )

            if hint.use:
                # neither of these nodes should be here yet?
                # bc this is a "new" hint with a new color
                #
                # assert(self.du_graph.has_node(def_node) == False)
                # assert(self.du_graph.has_node(use_node) == False)

                # this is a read -- dynamic value info is thus both defined and used
                ui = hint_def_use_info(hint)
                di = DefInfo(ui.info)

                def_node = ColorNode(hint.pc, hint.color)
                use_node = InstructionNode(hint.pc)
                self.du_graph.add_node(def_node)
                self.du_graph.add_node(use_node)

                # record mapping from this color to its creation info
                color2genesis[hint.color] = (def_node, di)

                # add an edge between color node and this instruction
                # that has def, use info (same)
                self.du_graph.add_def_use(
                    def_node=def_node,
                    use_node=use_node,
                    # note --- same def / use info here
                    def_info=di,
                    use_info=ui,
                    color=hint.color,
                )
            else:
                # this is a write of a new, and thus, computed value
                # record mapping from this color to its creation info
                def_node = InstructionNode(hint.pc)
                self.du_graph.add_node(def_node)
                di = hint_def_use_info(hint)
                color2genesis[hint.color] = (def_node, di)
                # note there is no edge here?
                # we just remember that this node created this color,
                # and also remember the DefInfo for that this write

        for hint in self.not_new_hints:
            # not a new color.  so its a flow

            # can't be a def
            assert "def" not in hint.message

            if not hint.use:
                # not new and not a use
                # so its a write of a previously created value
                # so this is a value copy; ignore
                pass
            else:
                # this is a flow, a read of a previously created color
                use_node = InstructionNode(hint.pc)
                self.du_graph.add_node(use_node)
                ui = hint_def_use_info(hint)
                (def_node, di) = color2genesis[hint.color]
                self.du_graph.add_def_use(
                    def_node=def_node,
                    use_node=use_node,
                    # note --- same def / use info here
                    def_info=di,
                    use_info=ui,
                    color=hint.color,
                )

        # hint out the def-use graph
        self.hinter.send(
            hinting.DefUseGraphHint(
                graph=nx.node_link_data(self.du_graph, edges="links"),
                message="concrete-summary-def-use-graph",
            )
        )

        with open("colorizer_def_use.dot", "w") as dot:

            def writeln(foo):
                dot.write(foo + "\n")

            writeln("digraph{")
            writeln(" rankdir=LR")

            node2nodeid = {}
            for node in self.du_graph.nodes:
                node_id = f"node_{len(node2nodeid)}"
                if type(node) is InstructionNode:
                    writeln(f'  {node_id} [label="pc=0x{node.pc:x}"]')
                elif type(node) is ColorNode:
                    writeln(
                        f'  {node_id} [color="blue", label="pc=0x{node.pc:x},color={node.color}"]'
                    )
                else:
                    assert 1 == 0
                node2nodeid[node] = node_id

            di = nx.get_edge_attributes(self.du_graph, "def_info")
            ui = nx.get_edge_attributes(self.du_graph, "use_info")
            assert di.color == ui.color

            for src, dst, k in self.du_graph.edges:
                hl = str(di)
                tl = str(ui)
                writeln(
                    f'  {node2nodeid[src]} -> {node2nodeid[dst]} [label="{di.color}",headlabel="{hl}",taillabel="{tl}"]'
                )

            writeln("}\n")

    def get_graph(self):
        return self.du_graph
