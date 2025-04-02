# mypy: ignore-errors

import sys
import typing

from .. import hinting
from . import analysis

hinter = hinting.get_hinter(__name__)

# goal here is to summarize across multiple micro execution if two
# hints map to the same key then they are in same equivalence class so
# we elide away things that will be specific to a run like micro exec
# number, color (actual dyn value), ptr addresses, etc.


def compute_dv_key(hint):
    if type(hint) is hinting.DynamicRegisterValueHint:
        return (
            ("type", "reg"),
            ("pc", hint.pc),
            ("size", hint.size),
            ("use", hint.use),
            ("new", hint.new),
            ("reg_name", hint.reg_name),
        )
    elif type(hint) is hinting.DynamicMemoryValueHint:
        return (
            ("type", "mem"),
            ("pc", hint.pc),
            ("size", hint.size),
            ("use", hint.use),
            ("new", hint.new),
            ("base", hint.base),
            ("index", hint.index),
            ("scale", hint.scale),
            ("offset", hint.offset),
        )
    elif type(hint) is hinting.MemoryUnavailableHint:
        return (
            ("type", "mem_unavail"),
            ("pc", hint.pc),
            ("size", hint.size),
            ("is_read", hint.is_read),
            ("base", hint.base_reg_name),
            ("index", hint.index_reg_name),
            ("scale", hint.scale),
            ("offset", hint.offset),
        )
    elif type(hint) is hinting.EmulationException:
        return (("type", "emu_fail"), ("pc", hint.pc), ("exception", hint.exception))

    else:
        # should never happen
        assert (
            (type(hint) is hinting.DynamicRegisterValueHint)
            or (type(hint) is hinting.DynamicMemoryValueHint)
            or (type(hint) is hinting.MemoryUnavailableHint)
            or (type(hint) is hinting.EmulationException)
        )


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
        print("activating colorizer_summary")
        self.listen(hinting.DynamicRegisterValueHint, self.collect_hints)
        self.listen(hinting.DynamicMemoryValueHint, self.collect_hints)
        self.listen(hinting.MemoryUnavailableHint, self.collect_hints)
        self.listen(hinting.EmulationException, self.collect_hints)

    def deactivate(self):
        # Establish true colors 1, 2, 3, ...
        #
        # The colors we have in hints are random initial reg or memory
        # values or values computed from those. This means they don't
        # correspond across micro-executions. We need them to do so if
        # we are to summarize.
        #
        truecolors = set([])
        dvh2truecolor = {}
        color2truecolor = {}
        for hint in self.hint_list:
            if hasattr(hint, "color"):
                if hint.new:
                    # This is a hint with a "new" color meaning the
                    # hint time is when the color was first
                    # observed. If we are trying to match up such new
                    # colors across micro executions, we do so by
                    # matching up the dv keys for them at this
                    # time of first observation.
                    dvk = compute_dv_key(hint)
                    dvh = hash(dvk) % ((sys.maxsize + 1) * 2)
                    if dvh not in dvh2truecolor:
                        # we need to establish a color for this dvh
                        next_color = 1 + len(truecolors)
                        truecolors.add(next_color)
                        dvh2truecolor[dvh] = next_color
                    # make sure to map every hint color to its true color
                    color2truecolor[hint.color] = dvh2truecolor[dvh]
                else:
                    assert hint.color in color2truecolor

        # use compute_dv_key to put keys into equiv classes
        # which works for both new and not-new hints
        # start off by collecting set of all such classes
        all_hint_keys = set([])
        hk_exemplar = {}
        for hint in self.hint_list:
            hk = compute_dv_key(hint)
            all_hint_keys.add(hk)
            # keep one exemplar for each equivalence class
            if hk not in hk_exemplar:
                hk_exemplar[hk] = hint

        hint_keys_sorted = sorted(list(all_hint_keys))

        # given the equivalence classes established by `compute_dv_key`, determine
        # which of those were observed in each micro-execution
        hk_observed: typing.Dict[
            int, typing.Set[typing.Tuple[int, bool, str, bool, str, str, str, int, int]]
        ] = {}
        for hint in self.hint_list:
            if hint.micro_exec_num not in hk_observed:
                hk_observed[hint.micro_exec_num] = set([])
                # this hint key was observed in micro execution me
            hk_observed[hint.micro_exec_num].add(compute_dv_key(hint))

        # get counts for hint across micro executions
        hk_c = {}
        for hk in hint_keys_sorted:
            hk_c[hk] = 0
            for me in range(1, 1 + self.num_micro_executions):
                for hk2 in hk_observed[me]:
                    if hk == hk2:
                        hk_c[hk] += 1

        for hk in hint_keys_sorted:
            hint = hk_exemplar[hk]
            if type(hint) is hinting.DynamicRegisterValueHint:
                hinter.info(
                    hinting.DynamicRegisterValueSummaryHint(
                        pc=hint.pc,
                        reg_name=hint.reg_name,
                        color=color2truecolor[hint.color],
                        size=hint.size,
                        use=hint.use,
                        new=hint.new,
                        count=hk_c[hk],
                        num_micro_executions=self.num_micro_executions,
                        message=hint.message + "-summary",
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
                        color=color2truecolor[hint.color],
                        use=hint.use,
                        new=hint.new,
                        message=hint.message + "-summary",
                        count=hk_c[hk],
                        num_micro_executions=self.num_micro_executions,
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
                        count=hk_c[hk],
                        num_micro_executions=self.num_micro_executions,
                        message=hint.message + "-summary",
                    )
                )
