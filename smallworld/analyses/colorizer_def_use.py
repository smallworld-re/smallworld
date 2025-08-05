# skdjfghdskfjmypy: ignore-errors

import re

import networkx as nx

from .. import hinting
from . import analysis

hinter = hinting.get_hinter(__name__)


class DefUseGraph(nx.MultiDiGraph):
    def add_def_use(self, def_node, use_node, def_info, use_info, color):
        self.add_edges_from(
            [
                (
                    def_node,
                    use_node,
                    {"def_info": def_info, "use_info": use_info, "color": color},
                )
            ]
        )


debug = True


class ColorizerDefUse(analysis.Filter):
    name = "colorizer_def_use_graph"
    description = "assemble a def use graph from colorizer summary hints"
    version = "0.0.1"

    def __init__(self):
        super().__init__()
        self.new_hints = []
        self.not_new_hints = []

    def collect_hints(self, hint: hinting.Hint):
        if type(hint) is hinting.DynamicRegisterValueSummaryHint or type(hint) is hinting.DynamicMemoryValueSummaryHint:
            if hint.new:
                self.new_hints.append(hint)
            else:
                self.not_new_hints.append(hint)

    def activate(self):
        self.listen(hinting.DynamicRegisterValueSummaryHint, self.collect_hints)
        self.listen(hinting.DynamicMemoryValueSummaryHint, self.collect_hints)

    def deactivate(self):
        du_graph = DefUseGraph()
        color2genesis = {}

        def hint_dv_info(hint):
            if type(hint) is hinting.DynamicRegisterValueSummaryHint:
                return {
                    "new": hint.new,
                    "count": hint.count,
                    "num_micro_executions": hint.num_micro_executions,
                    "type": "reg",
                    "is_read": hint.use,
                    "reg_name": hint.reg_name,
                    "color": hint.color,
                }
            elif type(hint) is hinting.DynamicMemoryValueSummaryHint:
                return {
                    "new": hint.new,
                    "count": hint.count,
                    "num_micro_executions": hint.num_micro_executions,
                    "type": "mem",
                    "is_read": hint.use,
                    "base": hint.base,
                    "index": hint.index,
                    "scale": hint.scale,
                    "offset": hint.offset,
                    "color": hint.color,
                }
            else:
                assert 1 == 0

        for hint in self.new_hints:
            # this is a new color so its either an input or a write of a computed value

            # some sanity checking
            assert "def" in hint.message
            assert hint.color not in color2genesis
            assert (hint.use and ("read" in hint.message)) or (
                (not hint.use) and ("write" in hint.message)
            )

            du_graph.add_node(hint.pc)

            dv_info = hint_dv_info(hint)

            if hint.use:
                # this is a read
                # hallucinate a node representing the creation of that color
                color_node = f"input color-{hint.color}"
                assert dv_info["type"] == "reg" or dv_info["type"] == "mem"

                if dv_info["type"] == "reg":
                    color_node = color_node + " " + dv_info["reg_name"]
                if dv_info["type"] == "mem":
                    color_node = color_node + " *(" + dv_info["base"]
                    if dv_info["index"] != "None":
                        color_node += f"{dv_info['scale']}*{dv_info['index']}"
                    if dv_info["offset"] > 0:
                        color_node += f"{dv_info['offset']}"
                    color_node += ")"
                color_node += "_init"
                du_graph.add_node(color_node)
                # record mapping from this color to its creation info
                color2genesis[hint.color] = (color_node, dv_info)
                # and an edge between that color node and this instruction
                du_graph.add_def_use(
                    color_node, hint.pc, color_node, dv_info, hint.color
                )
            else:
                # this is a write
                # record mapping from this color to its creation info
                color2genesis[hint.color] = (hint.pc, dv_info)

        for hint in self.not_new_hints:
            # not a new color.  so its a flow
            du_graph.add_node(hint.pc)
            # can't be a def
            assert "def" not in hint.message
            # we should never see !new && !use since that is just a value copy
            # assert hint.use
            if not hint.use:
                pass
            else:
                dv_info = hint_dv_info(hint)
                (def_node, def_info) = color2genesis[hint.color]
                du_graph.add_def_use(def_node, hint.pc, def_info, dv_info, hint.color)

        # hint out the def-use graph
        hinter.info(
            hinting.DefUseGraphHint(
                graph=nx.node_link_data(du_graph, edges="links"),
                message="concrete-summary-def-use-graph",
            )
        )

        with open("colorizer_def_use.dot", "w") as dot:

            def writeit(foo):
                dot.write(foo + "\n")

            writeit("digraph{")
            writeit(" rankdir=LR")

            node2nodeid = {}
            for node in du_graph.nodes:
                # 4461 is pc
                # {"id": 4461},
                # An input color rsp is register
                # {"id": "input color-1 rsp_init"},
                node_id = f"node_{len(node2nodeid)}"
                if type(node) is int:
                    # nodeinfo = ("instruction", f"0x{node}")
                    writeit(f'  {node_id} [label="0x{node:x}"]')
                else:
                    assert type(node) is str
                    foo = re.search("input color-([0-9]+) (.*)_init", node)
                    assert foo is not None
                    (cns, reg) = foo.groups()
                    cn = int(cns)
                    # nodeinfo = ("input", (cn, reg))
                    writeit(f'  {node_id} [color="blue", label="input({reg})"]')
                node2nodeid[node] = node_id

            di = nx.get_edge_attributes(du_graph, "def_info")
            ui = nx.get_edge_attributes(du_graph, "use_info")
            for e in du_graph.edges:
                if type(di[e]) is str:
                    foo = re.search("color-([0-9]+) (.*)_init", di[e])
                    (cns, reg) = foo.groups()
                    cn = int(cns)
                    assert cn == ui[e]["color"]
                else:
                    assert di[e]["color"] == ui[e]["color"]
                (src, dst, k) = e
                cn = ui[e]["color"]
                writeit(f'  {node2nodeid[src]} -> {node2nodeid[dst]} [label="{cn}"]')

            writeit("}\n")
