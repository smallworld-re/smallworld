# mypy: ignore-errors

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
        self.du_graph = DefUseGraph()
        self.color2nodeDv = {}        
    
    def collect_def_use(self, hint: hinting.Hint):
        self.du_graph.add_node(hint.pc)
        if type(hint) is hinting.DynamicRegisterValueSummaryHint:
            dv_info = [
                ("count", hint.count),
                ("num_micro_executions", hint.num_micro_executions),
                ("prob", (float(hint.count)/hint.num_micro_executions)),
                ("type", "reg"),
                ("reg_name", hint.reg_name),
            ]
        elif type(hint) is hinting.DynamicMemoryValueSummaryHint:
            dv_info = [
                ("count", hint.count),
                ("num_micro_executions", hint.num_micro_executions),
                ("prob", (float(hint.count)/hint.num_micro_executions)),
                ("type", "mem"),
                ("base", hint.base),
                ("index", hint.index),
                ("scale", hint.scale),
                ("offset", hint.offset),
            ]
        else:
            assert ((type(hint) is hinting.DynamicRegisterValueSummaryHint) or (type(hint) is hinting.DynamicMemoryValueSummaryHint))
        
        if hint.new:
            # this is a new color so its either an input or a write of a computed value
            assert "def" in hint.message
            assert hint.color not in self.color2nodeDv
            if hint.use:
                assert "read" in hint.message
                self.color2nodeDv[hint.color] = (hint.pc, dv_info)
            else:
                assert "write" in hint.message
                self.color2nodeDv[hint.color] = (hint.pc, dv_info)
            # if its a read then
            # hallucinate a node representing the creation of that color
            if hint.use:
                color_node = f"input color-{hint.color}"
                self.du_graph.add_node(color_node)
                self.color2nodeDv[hint.color] = (color_node, None)
                # and an edge between that and this instruction
                self.du_graph.add_def_use(
                    color_node, hint.pc, color_node, dv_info, hint.color
                )
        else:
            # not a new color.  so its a flow
            assert "def" not in hint.message
            # we should never see new && !use since that is just a value copy

            # assert hint.use
            (def_node, def_dv_info) = self.color2nodeDv[hint.color]
            self.du_graph.add_def_use(def_node, hint.pc, def_dv_info, dv_info, hint.color)

    def activate(self):
        print("activating colorizer_def_use_graph")
        self.listen(hinting.DynamicRegisterValueSummaryHint, self.collect_def_use)
        self.listen(hinting.DynamicMemoryValueSummaryHint, self.collect_def_use)

    def deactivate(self):
        # hint out the def-use graph
        hinter.info(
            hinting.DefUseGraphHint(
                graph = str(nx.node_link_data(self.du_graph)),
                message = "concrete-def-use-graph"
            )
        )
            
