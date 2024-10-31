# mypy: ignore-errors
import logging

import networkx as nx

from ... import hinting
from .. import analysis

hinter = hinting.get_hinter(__name__)
logger = logging.getLogger(__name__)


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


du_graph = DefUseGraph()
color2nodeDv = {}


class ColorizerSummary(analysis.Filter):
    name = "colorizer_summary"
    description = "summarized version of colorizer"
    version = "0.0.1"

    @staticmethod
    def dynamic_value_summary(hint: hinting.Hint):
        #        print(hint)
        # instr_node = hint.instruction
        # du_graph.add_node(instr_node)
        du_graph.add_node(hint.pc)
        if type(hint) is hinting.DynamicRegisterValueProbHint:
            dv_info = [
                ("prob", hint.prob),
                ("type", "reg"),
                ("reg_name", hint.reg_name),
            ]
        elif type(hint) is hinting.DynamicMemoryValueProbHint:
            dv_info = [
                ("prob", hint.prob),
                ("type", "mem"),
                ("base", hint.base),
                ("index", hint.index),
                ("scale", hint.scale),
                ("offset", hint.offset),
            ]
        else:
            assert 1 == 0
        if hint.new:
            # this is a new color so its either an input or a write of a computed value
            assert "def" in hint.message
            assert hint.color not in color2nodeDv
            if hint.use:
                assert "read" in hint.message
                # color2nodeDv[hint.color] = (instr_node, dv_info)
                color2nodeDv[hint.color] = (hint.pc, dv_info)
            else:
                assert "write" in hint.message
                color2nodeDv[hint.color] = (hint.pc, dv_info)
            # if its a read then
            # hallucinate a node representing the creation of that color
            if hint.use:
                color_node = f"input color-{hint.color}"
                du_graph.add_node(color_node)
                color2nodeDv[hint.color] = (color_node, None)
                # and an edge between that and this instruction
                du_graph.add_def_use(
                    color_node, hint.pc, color_node, dv_info, hint.color
                )
        else:
            # not a new color.  so its a flow
            assert "def" not in hint.message
            # we should never see new && !use since that is just a value copy

            # assert hint.use
            (def_node, def_dv_info) = color2nodeDv[hint.color]
            du_graph.add_def_use(def_node, hint.pc, def_dv_info, dv_info, hint.color)

    def activate(self):
        # pdb.set_trace()
        print("activating colorizer_summary")
        self.listen(hinting.DynamicRegisterValueProbHint, self.dynamic_value_summary)
        self.listen(hinting.DynamicMemoryValueProbHint, self.dynamic_value_summary)

    def deactivate(self):
        # import pdb
        # pdb.set_trace()

        jsg = nx.node_link_data(du_graph)
        with open("dugraph.json", "w") as j:
            j.write(str(jsg))
