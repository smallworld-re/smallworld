# mypy: ignore-errors

from .. import hinting
from . import analysis

hinter = hinting.get_hinter(__name__)
            
            
class ColorizerSummary(analysis.Filter):
    name = "colorizer_summary"
    description = "collect and summarize colorizer output across micro executions"
    version = "0.0.1"

    def __init__(self):
        super().__init__()
        self.hint_list = []
        self.num_micro_executions = 0
        
    def collect_hints(self, hint):
        self.hint_list.append(hint)
        if hint.micro_exec_num > self.num_micro_executions:
            self.num_micro_executions = hint.micro_exec_num
                
    def activate(self):
        # pdb.set_trace()
        print("activating colorizer_summary")
        self.listen(hinting.DynamicRegisterValueHint, self.collect_hints)
        self.listen(hinting.DynamicMemoryValueHint, self.collect_hints)
        self.listen(hinting.MemoryUnavailableHint, self.collect_hints)
        self.listen(hinting.EmulationException, self.collect_hints)
        
    def deactivate(self):

        # if two hints map to the same key then they are in same equivalence class
        def hint_key(hint):
            if type(hint) is hinting.DynamicRegisterValueHint:
                return (
                    "dynamic_register_value",
                    hint.pc,
                    not hint.use,
                    hint.color,
                    hint.new,
                    hint.message,
                    hint.reg_name,
                )
            if type(hint) is hinting.DynamicMemoryValueHint:
                return (
                    "dynamic_memory_value",
                    hint.pc,
                    not hint.use,
                    hint.color,
                    hint.new,
                    hint.message,
                    hint.base,
                    hint.index,
                    hint.scale,
                    hint.offset,
                )
            if type(hint) is hinting.MemoryUnavailableHint:
                return (
                    "memory_unavailable",
                    hint.pc,
                    hint.size,
                    hint.message,
                    hint.base_reg_name,
                    hint.index_reg_name,
                    hint.offset,
                    hint.scale,
                )
            if type(hint) is hinting.EmulationException:
                return (
                    "emulation_exception",
                    hint.pc,
                    hint.instruction_num,
                    hint.exception,
                )
            
        all_hint_keys = set([])
        hk_exemplar = {}
        for hint in self.hint_list:
            hk = hint_key(hint)
            all_hint_keys.add(hk)
            # keep one exemplar
            if hk not in hk_exemplar:
                hk_exemplar[hk] = hint

        hint_keys_sorted = sorted(list(all_hint_keys))

        # given the equivalence classes established by `hint_key`, determine
        # which of those were observed in each micro-execution
        hk_observed: typing.Dict[
            int, typing.Set[typing.Tuple[int, bool, str, bool, str, str, str, int, int]]
        ] = {}
        for hint in self.hint_list:
            if hint.micro_exec_num not in hk_observed:
                hk_observed[hint.micro_exec_num] = set([])
                # this hint key was observed in micro execution me                
            hk_observed[hint.micro_exec_num].add(hint_key(hint))
            
        # estimate "probability" of observing a hint in an equiv class as
        # fraction of micro executions in which it was observed at least once
        hk_c = {}
        for hk in hint_keys_sorted:
            hk_c[hk] = 0
            for me in range(self.num_micro_executions):
                for hk2 in hk_observed[me]:
                    if hk == hk2:
                        hk_c[hk] += 1

        for hk in hint_keys_sorted:
            hint = hk_exemplar[hk]
            #import pdb
            #pdb.set_trace()
            if type(hint) is hinting.DynamicRegisterValueHint:
                hinter.info(
                    hinting.DynamicRegisterValueSummaryHint(
                        pc=hint.pc,
                        reg_name=hint.reg_name,
                        color=hint.color,
                        size=hint.size,
                        use=hint.use,
                        new=hint.new,
                        count = hk_c[hk],
                        num_micro_executions = self.num_micro_executions,
                        message=hint.message + "-prob",
                    )
                )
            if type(hint) is hinting.DynamicMemoryValueHint:
                hinter.info(
                    hinting.DynamicMemoryValueSummaryHint(
                        pc=hint.pc,
                        size=hint.size,
                        base=hint.base,
                        index=hint.index,
                        scale=hint.scale,
                        offset=hint.offset,
                        color=hint.color,
                        use=hint.use,
                        new=hint.new,
                        message=hint.message + "-prob",
                        count = hk_c[hk],
                        num_micro_executions = self.num_micro_executions,
                    )
                )
            if type(hint) is hinting.MemoryUnavailableHint:
                hinter.info(
                    hinting.MemoryUnavailableSummaryHint(
                        is_read=hint.is_read,
                        size=hint.size,
                        base_reg_name=hint.base_reg_name,
                        index_reg_name=hint.index_reg_name,
                        offset=hint.offset,
                        scale=hint.scale,
                        pc=hint.pc,
                        count = hk_c[hk],
                        num_micro_executions = self.num_micro_executions,
                        message=hint.message + "-prob",
                    )
                )
