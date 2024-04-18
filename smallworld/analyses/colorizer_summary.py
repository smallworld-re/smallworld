import logging
import pdb

from networkx import MultiDiGraph

from .. import hinting
from . import analysis

hinter = hinting.getHinter(__name__)
logger = logging.getLogger(__name__)


class DefUseGraph(MultiDiGraph):
    def __init__(self):
        self.g = MultiDiGraph()

    def add_def_use(self, def_node, use_node, def_info, use_info, tag):
        self.g.add_edges_from(
            [
                (
                    def_node,
                    use_node,
                    {"def_info": def_info, "use_info": use_info, "tag": tag},
                )
            ]
        )


du_graph = MultiDiGraph()
color2nodeDv = {}


class ColorizerSummary(analysis.Filter):
    name = "colorizer_summary"
    description = "summarized version of colorizer"
    version = "0.0.1"

    @staticmethod
    def dynamic_value_summary(hint):
        print(hint)
        instr_node = hint.instruction
        du_graph.add_node(instr_node)
        if type(hint) is hinting.DynamicRegisterValueProbHint:
            dv_info = ["reg", hint.instruction, hint.prob, hint.reg_name]
        elif type(hint) is hinting.DynamicMemoryValueProbHint:
            dv_info = [
                "mem",
                hint.instruction,
                hint.prob,
                hint.size,
                hint.base,
                hint.index,
                hint.scale,
            ]
        else:
            assert 1 == 0
        if hint.new:
            # this is a new color so its either an input or a write of a computed value
            assert "def" in hint.message
            assert hint.color not in color2nodeDv
            if hint.use:
                assert "read" in hint.message
                color2nodeDv[hint.color] = (instr_node, dv_info, "read_def")
            else:
                assert "write" in hint.message
                color2nodeDv[hint.color] = (instr_node, dv_info, "write_def")
        else:
            # not a new color.  so its a flow
            assert "def" not in hint.message
            # we should never see new && !use since that is just a value copy
            assert hint.use
            (def_node, def_dv_info, tag) = color2nodeDv[hint.color]
            du_graph.add_def_use(def_node, instr_node, def_dv_info, dv_info, tag)

    def activate(self):
        # pdb.set_trace()
        print("activating colorizer_summary")
        self.listen(hinting.DynamicRegisterValueProbHint, self.dynamic_value_summary)
        self.listen(hinting.DynamicMemoryValueProbHint, self.dynamic_value_summary)


#    def deactivate(self):
#        pdb.set_trace()
#        print("deactivating this thing")
