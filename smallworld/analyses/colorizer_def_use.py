import logging
import typing
from dataclasses import dataclass

import networkx as nx

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
        logger.info("add_def_use")
        logger.info(f"  def_node={def_node}")
        logger.info(f"  def_info={def_info}")
        logger.info(f"  use_node={use_node}")
        logger.info(f"  use_info={use_info}")

        self.add_edges_from(
            [
                (
                    def_node,
                    use_node,
                    {"def_info": def_info, "use_info": use_info, "color": color},
                )
            ]
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
        return f"InstructionNode(pc={self.pc:x})"

    def str_short(self):
        return f"pc=0x{self.pc:x}"

    def __hash__(self):
        return hash(self.__str__())


@dataclass
class ColorNode(DefUseNode):
    color: int

    def __str__(self: typing.Any):
        return f"ColorNode(pc={self.pc:x},color={self.color})"

    def str_short(self):
        return f"color={self.color}\npc=0x{self.pc:x}"

    def __hash__(self):
        return hash(self.__str__())


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

    def str_short(self):
        return f"{self.register.name}"


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

    def str_short(self):
        return self.bsid.expr_string()


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
            base, index = None, None

            # deal with None fields represented as "None"
            def snull(hint, field):
                if hasattr(hint, field):
                    attr = getattr(hint, field)
                    if attr == "None":
                        return None
                    else:
                        return attr
                return None

            base = snull(hint, "base")
            index = snull(hint, "index")

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
                                base, index, hint.scale, hint.offset
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
                                base, index, hint.scale, hint.offset
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

            logger.info(f"new hint: {hint}")
            # some sanity checking
            assert "def" in hint.message
            # if hint.color in color2genesis:
            #     breakpoint()
            assert hint.color not in color2genesis
            assert (hint.use and ("read" in hint.message)) or (
                (not hint.use) and ("write" in hint.message)
            )
            # if hint.pc == 0x2191:
            #     breakpoint()

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

            # if hint.pc == 0x2191:
            #     breakpoint()

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

        # determine node labels
        node2attr = {}
        node2nodeid = {}
        for node in self.du_graph.nodes:
            node_id = f"node_{len(node2nodeid)}"
            node2nodeid[node] = node_id
            if type(node) is InstructionNode:
                node2attr[node] = {"label": f"pc=0x{node.pc:x}"}
            elif type(node) is ColorNode:
                node2attr[node] = {"label": f"color={node.color}", "color": "blue"}
            else:
                assert 1 == 0

        di = nx.get_edge_attributes(self.du_graph, "def_info")
        ui = nx.get_edge_attributes(self.du_graph, "use_info")

        # determine edge labels
        edge2labels = {}
        for node in self.du_graph.nodes:

            def get_labels(edge):
                hl = ui[edge].info.str_short()
                tl = di[edge].info.str_short()
                color = di[edge].info.color
                color == ui[edge].info.color
                lab = f"{color}"
                # if hl == tl:
                #    lab = f"{color},{hl}"
                #    tl = ""
                #    hl = ""
                # else:
                #    tl = f"{color},{tl}"
                #    lab = ""
                return (hl, tl, lab)

            # set all the edge labels
            for edge in self.du_graph.edges:
                (src, dst, _) = edge
                if src == node:
                    # edge is an out-edge for src
                    edge2labels[edge] = get_labels(edge)

            # determine if all out-edges for src `node` have same
            # `def` label
            tl_first = None
            same = True
            print(f"src={node}")
            for edge in self.du_graph.edges:
                (src, dst, _) = edge
                if src == node:
                    # edge is an out-edge for src
                    (hl, tl, lab) = get_labels(edge)
                    if tl_first is None:
                        tl_first = tl
                        print(f"  dst={dst}, tl_first = [{tl_first}]")
                    else:
                        if tl != tl_first:
                            print(f"  dst={dst}, tl = [{tl}] NOT SAME")
                            same = False
                        else:
                            print(f"  dst={dst}, tl = [{tl}] same")
            # if they do, we discard all the def labels but first label on
            if same:
                print(" SAME!")
                first = True
                for edge in self.du_graph.edges:
                    (src, dst, _) = edge
                    if src == node:
                        # edge is an out-edge for src
                        if first:
                            # leave the label for this edge alone
                            first = False
                        else:
                            (hl, tl, lab) = edge2labels[edge]
                            edge2labels[edge] = (hl, "", lab)
            else:
                print(" Not same")

        for edge in self.du_graph.edges:
            (src, dst, _) = edge
            (hl, tl, lab) = edge2labels[edge]
            if hl == tl:
                edge2labels[edge] = ("", "", f"{lab},{tl}")

        with open("colorizer_def_use.dot", "w") as dot:

            def writeln(foo):
                dot.write(foo + "\n")

            writeln("digraph{")
            writeln(" rankdir=LR")

            for node in self.du_graph.nodes:
                attrsstr = ",".join([f'{k}="{v}"' for k, v in node2attr[node].items()])
                writeln(f"  {node2nodeid[node]} [{attrsstr}]")

            for edge in self.du_graph.edges:
                (hl, tl, lab) = edge2labels[edge]
                (src, dst, k) = edge
                writeln(
                    f'  {node2nodeid[src]} -> {node2nodeid[dst]} [label="{lab}",headlabel="{hl}",taillabel="{tl}"]'
                )

            writeln("}\n")

            # node2nodeid = {}
            # for node in self.du_graph.nodes:
            #     node_id = f"node_{len(node2nodeid)}"
            #     if type(node) is InstructionNode:
            #         writeln(f'  {node_id} [label="pc=0x{node.pc:x}"]')
            #     elif type(node) is ColorNode:
            #         writeln(
            #             f'  {node_id} [color="blue", label="color={node.color}"]'
            #         )
            #     else:
            #         assert 1 == 0
            #     node2nodeid[node] = node_id

            # di = nx.get_edge_attributes(self.du_graph, "def_info")
            # ui = nx.get_edge_attributes(self.du_graph, "use_info")

            # for e in self.du_graph.edges:
            #     hl = ui[e].info.str_short()
            #     tl = di[e].info.str_short()
            #     color = di[e].info.color
            #     color == ui[e].info.color
            #     if hl == tl:
            #         lab = f"{color},{hl}"
            #         tl = ""
            #         hl = ""
            #     else:
            #         tl = f"{color},{tl}"
            #         lab = ""
            #         (src, dst, k) = e
            #         writeln(
            #             f'  {node2nodeid[src]} -> {node2nodeid[dst]} [label="{lab}",headlabel="{hl}",taillabel="{tl}"]'
            #         )

            # writeln("}\n")

    def get_graph(self):
        return self.du_graph
