# mypy: ignore-errors

import functools

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


class ColorizerDefUse(analysis.Filter):
    name = "colorizer_def_use_graph"
    description = "assemble a def use graph from colorizer summary hints"
    version = "0.0.1"

    def __init__(self):
        super().__init__()
        self.new_hints = []
        self.not_new_hints = []

    def collect_hints(self, hint: hinting.Hint):
        if hint.new:
            self.new_hints.append(hint)
        else:
            self.not_new_hints.append(hint)

    def activate(self):
        print("activating colorizer_def_use_graph")
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
                assert dv_info["type"] == "reg"
                if dv_info["type"] == "reg":
                    color_node = color_node + " " + dv_info["reg_name"] + "_init"

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
                graph=str(nx.node_link_data(du_graph, edges="links")),
                message="concrete-summary-def-use-graph",
            )
        )

        nodes = []
        for node in du_graph.nodes:
            nodes.append(node)

        def cmp_n(n1, n2):
            if isinstance(n1, type(n2)):
                if n1 < n2:
                    return -1
                if n1 == n2:
                    return 0
                return +1
            if type(n1) is str:
                return -1
            else:
                return +1

        # sorted: strings like "input-color-.." come first, then
        # numbers which are program counters in order
        snodes = sorted(nodes, key=functools.cmp_to_key(cmp_n))

        def_info = nx.get_edge_attributes(du_graph, "def_info")
        use_info = nx.get_edge_attributes(du_graph, "use_info")

        def node_str(node):
            if type(node) is str:
                return node
            else:
                return f"0x{node:x}"

        def simple_info(info):
            if info is None:
                return "none"
            if type(info) is str:
                return info
            if info["type"] == "reg":
                return f"is_read={info['is_read']} new={info['new']} color={info['color']} Reg({info['reg_name']})"
            bsid = ""
            if info["base"] != "None":
                bsid += f"{info['base']}"
            if info["index"] != "None":
                bsid += f"+ {info['scale']}*{info['index']}"
            if info["offset"] != 0:
                bsid += f"+ {info['offset']:x}"
            return f"is_read={info['is_read']} new={info['new']} color={info['color']} Mem({bsid})"

        def simple_node(n):
            if n is None:
                return ""
            if type(n) is str:
                return n
            return f"0x{n:x}"

        for node in snodes:
            print(f"\nNODE: {node_str(node)}")
            for src, dst in du_graph.in_edges(node):
                if (src, dst, 0) in use_info:
                    ssrc = simple_node(src)
                    sdst = simple_node(dst)
                    di = simple_info(def_info[(src, dst, 0)])
                    ui = simple_info(use_info[(src, dst, 0)])
                    print(f"in-edge src=({ssrc},{di}) dst=({sdst},{ui})")
            for src, dst in du_graph.out_edges(node):
                if (src, dst, 0) in def_info:
                    ssrc = simple_node(src)
                    sdst = simple_node(dst)
                    di = simple_info(def_info[(src, dst, 0)])
                    ui = simple_info(use_info[(src, dst, 0)])
                    print(f"out-edge src=({ssrc},{di}) dst=({sdst},{ui})")
