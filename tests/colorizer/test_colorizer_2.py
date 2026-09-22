# type: ignore
import truth_data
from colorizer_test import test

from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
    TraceExecutionHint,
)

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos randomize_regs, seed)
    #
    # foo function in ahme.c (trace_executor dir) is what is
    # harnessed / analyzed by the test function
    #
    # Also, buflen bigger than min color 0x80 thus we *will* actually
    # get derivation for buflen back to esi (2nd arg to foo).
    #
    derivations, hints = test(
        5,  # num micro executions
        180,  # max instructions per micro execution
        47,  # buffer length (set to 47 here which is magic)
        True,  # buffer needs to contain a lot of 42s since we arent in magic bit
        1234,  # seed (since `test` generates a random buffer)
    )

    # collect all pcs in any trace
    # also tds which is set of digests for a trace
    tds = set([])
    i = 0
    all_pcs = set([])
    for h in hints:
        if type(h) is TraceExecutionHint:
            tds.add(h.trace_digest)
            for te in h.trace:
                all_pcs.add(te.pc)
            i += 1

    num_expected = 0
    num_unexpected = 0

    def expected(cond, msge, msgu):
        global num_expected, num_unexpected
        if cond:
            print(f"EXPECTED  {msge}")
            num_expected += 1
            return True
        else:
            print(f"UNEXPECTED {msgu}")
            num_unexpected += 1
            return False

    truth_all_pcs, truth_summ, correct_derivations = truth_data.load("test_colorizer_2")

    expected(
        all_pcs == truth_all_pcs,
        "set of pcs is same for truth and observed",
        "set of pcs disagrees between truth and observed",
    )

    expected(
        i == 5, "five trace execution hints", f"{i} trace execution hints. 5 expected"
    )

    expected(
        len(tds) == 5,
        "5 unique traces",
        f"num unique traces is {len(tds)}. 5 expected",
    )

    observed_summ = {}
    for h in hints:
        if type(h) in set(
            [DynamicMemoryValueSummaryHint, DynamicRegisterValueSummaryHint]
        ):
            if h.pc not in observed_summ:
                observed_summ[h.pc] = []
            observed_summ[h.pc].append(h)

    observed_summ_pcs = set(list(observed_summ.keys()))

    truth_summ_pcs = set(list(truth_summ.keys()))
    expected(
        truth_summ_pcs == observed_summ_pcs,
        "set of pcs observed for summary hints same as truth",
        "pcs observed for summary hints not same as truth",
    )

    for pc in all_pcs:
        if pc in truth_summ_pcs and pc in observed_summ_pcs:
            if not expected(
                observed_summ[pc] == truth_summ[pc],
                f"list of hints observed for pc={pc} same as truth",
                f"list of hints observed for pc={pc} not same as for truth",
            ):
                print(f"Truth:    {truth_summ[pc]}")
                print(f"Observed: {observed_summ[pc]}")
        elif pc in truth_summ_pcs:
            print(f"{truth_summ[pc]} is in truth only")
        elif pc in observed_summ_pcs:
            print(f"{observed_summ[pc]} in observed only")
        else:
            pass

    expected(
        len(derivations) == len(correct_derivations),
        "number of derivations is correct",
        f"expected{len(correct_derivations)} derivations, but got {len(derivations)}",
    )

    for i in range(len(correct_derivations)):
        cpc, cvals, cder = correct_derivations[i]
        opc, ovals, oder = derivations[i]
        expected(
            (cpc == opc) and (cvals == ovals) and (cder == oder),
            f"derivation for {cvals} @ {cpc:x} is correct: {cder}",
            f"derivation for {cvals} @ {cpc:x} is incorrect: {oder}",
        )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
