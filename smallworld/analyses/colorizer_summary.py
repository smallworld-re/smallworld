import logging
import pdb

from .. import hinting
from . import analysis

hinter = hinting.getHinter(__name__)
logger = logging.getLogger(__name__)


class ColorizerSummary(analysis.Filter):
    name = "colorizer_summary"
    description = "summarized version of colorizer"
    version = "0.0.1"

    @staticmethod
    def dynamic_value_summary(hint):
        # summarize hints
        print(f"in dynamic_value_summary {hint}")
        pdb.set_trace()
        print("HELLO ALEX")
        if type(hint) is hinting.DynamicRegisterValueProbHint:
            pdb.set_trace()
            print(
                f"XXX p={hint.prob} mesg={hint.message} pc={hint.pc} color={hint.color}\n"
            )
            print("HELLO")
        if type(hint) is hinting.DynamicMemoryValueProbHint:
            pdb.set_trace()
            print(
                f"YYY p={hint.prob} mesg={hint.message} pc={hint.pc} color={hint.color}\n"
            )
            print("GOODBYE")

    def activate(self):
        pdb.set_trace()
        print("activating colorizer_summary")
        self.listen(hinting.DynamicRegisterValueProbHint, self.dynamic_value_summary)
        self.listen(hinting.DynamicMemoryValueProbHint, self.dynamic_value_summary)
