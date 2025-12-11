# type: ignore
from colorizer_test import test

from smallworld.analyses.colorizer_read_write import MemoryLvalInfo, RegisterInfo
from smallworld.hinting.hints import (
    DynamicMemoryValueSummaryHint,
    DynamicRegisterValueSummaryHint,
    TraceExecutionHint,
)
from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.platforms.defs.platformdef import RegisterDef

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos randomize_regs, seed)
    #
    # foo function in ahme.c (trace_executor dir) is what is
    # harnessed / analyzed by the test function
    #
    # Also, buflen bigger than min color 0x80 thus we *will* actually
    # get derivation for buflen back to esi (2nd arg to foo).
    #
    (derivations, hints) = test(
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

    truth_all_pcs = {
        0x2181,
        0x2202,
        0x2183,
        0x2205,
        0x2186,
        0x218D,
        0x218F,
        0x2192,
        0x2195,
        0x2199,
        0x219C,
        0x219F,
        0x21A4,
        0x21A6,
        0x21A8,
        0x21AC,
        0x21AE,
        0x21B1,
        0x21B3,
        0x21B5,
        0x21B7,
        0x21B9,
        0x21BB,
        0x21BD,
        0x21BF,
        0x21C1,
        0x21C4,
        0x21C6,
        0x21C8,
        0x21CA,
        0x21CD,
        0x21CF,
        0x21D2,
        0x21D4,
        0x21D7,
        0x2159,
        0x215A,
        0x21D9,
        0x21DB,
        0x215D,
        0x21DD,
        0x21E0,
        0x2161,
        0x21E3,
        0x2164,
        0x21E6,
        0x2167,
        0x21EA,
        0x21ED,
        0x216E,
        0x21F0,
        0x2172,
        0x21F2,
        0x21F4,
        0x2178,
        0x21FB,
        0x217C,
        0x217E,
        0x21FF,
    }

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

    truth_summ = {
        8537: [
            DynamicMemoryValueSummaryHint(
                message="write-copy-summary",
                pc=8537,
                color=1,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[
                    4885445162691904961,
                    13460321687654991269,
                    9280256056959569510,
                    9814421962479061546,
                    18306165297079870698,
                ],
                num_micro_executions=5,
                base="rsp",
                index="None",
                scale=1,
                offset=0,
                addresses=[81912],
            ),
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8537,
                color=3,
                size=8,
                use=False,
                new=True,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rsp",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-def-summary",
                pc=8537,
                color=1,
                size=8,
                use=True,
                new=True,
                count=5,
                dynamic_values=[
                    4885445162691904961,
                    13460321687654991269,
                    9280256056959569510,
                    9814421962479061546,
                    18306165297079870698,
                ],
                num_micro_executions=5,
                reg_name="rbp",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-def-summary",
                pc=8537,
                color=2,
                size=8,
                use=True,
                new=True,
                count=5,
                dynamic_values=[81920],
                num_micro_executions=5,
                reg_name="rsp",
            ),
        ],
        8541: [
            DynamicMemoryValueSummaryHint(
                message="write-copy-summary",
                pc=8541,
                color=4,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                base="rbp",
                index="None",
                scale=1,
                offset=-24,
                addresses=[81888],
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8541,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-def-summary",
                pc=8541,
                color=4,
                size=8,
                use=True,
                new=True,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rdi",
            ),
        ],
        8548: [
            DynamicMemoryValueSummaryHint(
                message="write-copy-summary",
                pc=8548,
                color=5,
                size=4,
                use=False,
                new=False,
                count=5,
                dynamic_values=[
                    2558659334,
                    3585948327,
                    1698482380,
                    2568261659,
                    2583265852,
                ],
                num_micro_executions=5,
                base="rbp",
                index="None",
                scale=1,
                offset=-32,
                addresses=[81880],
            ),
            DynamicRegisterValueSummaryHint(
                message="read-def-summary",
                pc=8548,
                color=5,
                size=4,
                use=True,
                new=True,
                count=5,
                dynamic_values=[
                    2558659334,
                    3585948327,
                    1698482380,
                    2568261659,
                    2583265852,
                ],
                num_micro_executions=5,
                reg_name="edx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8548,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
        ],
        8568: [
            DynamicMemoryValueSummaryHint(
                message="read-flow-summary",
                pc=8568,
                color=5,
                size=4,
                use=True,
                new=False,
                count=5,
                dynamic_values=[
                    2558659334,
                    3585948327,
                    1698482380,
                    2568261659,
                    2583265852,
                ],
                num_micro_executions=5,
                base="rbp",
                index="None",
                scale=1,
                offset=-32,
                addresses=[81880],
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8568,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
        ],
        8597: [
            DynamicMemoryValueSummaryHint(
                message="read-flow-summary",
                pc=8597,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                base="rbp",
                index="None",
                scale=1,
                offset=-24,
                addresses=[81888],
            ),
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8597,
                color=4,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8597,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
        ],
        8604: [
            DynamicMemoryValueSummaryHint(
                message="read-def-summary",
                pc=8604,
                color=10,
                size=1,
                use=True,
                new=True,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                base="rax",
                index="None",
                scale=1,
                offset=0,
                addresses=[131074, 131075, 131076],
            ),
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8604,
                color=10,
                size=4,
                use=False,
                new=False,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                reg_name="edx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8604,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072, 131073, 131074, 131075, 131076],
                num_micro_executions=5,
                reg_name="rax",
            ),
        ],
        8678: [
            DynamicMemoryValueSummaryHint(
                message="read-flow-summary",
                pc=8678,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                base="rbp",
                index="None",
                scale=1,
                offset=-24,
                addresses=[81888],
            ),
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8678,
                color=4,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8678,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
        ],
        8685: [
            DynamicMemoryValueSummaryHint(
                message="read-flow-summary",
                pc=8685,
                color=10,
                size=1,
                use=True,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                base="rax",
                index="None",
                scale=1,
                offset=0,
                addresses=[131074, 131075],
            ),
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8685,
                color=10,
                size=4,
                use=False,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8685,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072, 131073, 131074, 131075],
                num_micro_executions=5,
                reg_name="rax",
            ),
        ],
        8538: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8538,
                color=3,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8538,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rsp",
            ),
        ],
        8545: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8545,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8551: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8551,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8558: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8558,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8574: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8574,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8579: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8579,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8582: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8582,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8591: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8591,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8601: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8601,
                color=4,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rax",
            ),
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8601,
                color=7,
                size=8,
                use=False,
                new=True,
                count=5,
                dynamic_values=[131073, 131074, 131075, 131076],
                num_micro_executions=5,
                reg_name="rax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8601,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rax",
            ),
        ],
        8614: [
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8614,
                color=8,
                size=1,
                use=False,
                new=True,
                count=4,
                dynamic_values=[224, 170, 138, 240, 148, 250, 254],
                num_micro_executions=5,
                reg_name="al",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8614,
                color=10,
                size=1,
                use=True,
                new=False,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                reg_name="dl",
            ),
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8614,
                color=6,
                size=2,
                use=False,
                new=False,
                count=5,
                dynamic_values=[3612],
                num_micro_executions=5,
                reg_name="ax",
            ),
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8614,
                color=6,
                size=2,
                use=False,
                new=True,
                count=5,
                dynamic_values=[
                    6880,
                    56420,
                    516,
                    4988,
                    10922,
                    61322,
                    63472,
                    8084,
                    64762,
                    3612,
                    10750,
                ],
                num_micro_executions=5,
                reg_name="ax",
            ),
        ],
        8616: [
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8616,
                color=10,
                size=2,
                use=False,
                new=True,
                count=3,
                dynamic_values=[239, 220, 252, 247],
                num_micro_executions=5,
                reg_name="ax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8616,
                color=6,
                size=2,
                use=True,
                new=False,
                count=5,
                dynamic_values=[
                    6880,
                    56420,
                    516,
                    4988,
                    10922,
                    61322,
                    63472,
                    8084,
                    64762,
                    3612,
                    10750,
                ],
                num_micro_executions=5,
                reg_name="ax",
            ),
        ],
        8620: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8620,
                color=10,
                size=4,
                use=False,
                new=False,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                reg_name="ecx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8620,
                color=10,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                reg_name="edx",
            ),
        ],
        8622: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8622,
                color=11,
                size=1,
                use=False,
                new=False,
                count=1,
                dynamic_values=[255],
                num_micro_executions=5,
                reg_name="cl",
            ),
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8622,
                color=11,
                size=1,
                use=False,
                new=True,
                count=3,
                dynamic_values=[255],
                num_micro_executions=5,
                reg_name="cl",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8622,
                color=10,
                size=1,
                use=True,
                new=False,
                count=3,
                dynamic_values=[232, 207, 150, 247],
                num_micro_executions=5,
                reg_name="cl",
            ),
        ],
        8625: [
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8625,
                color=12,
                size=4,
                use=False,
                new=True,
                count=3,
                dynamic_values=[4294967261, 4294967280, 4294967288, 4294967293],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8625,
                color=10,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[239, 220, 252, 247],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8625,
                color=11,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[255],
                num_micro_executions=5,
                reg_name="ecx",
            ),
        ],
        8627: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8627,
                color=12,
                size=4,
                use=False,
                new=False,
                count=3,
                dynamic_values=[4294967261, 4294967280, 4294967288, 4294967293],
                num_micro_executions=5,
                reg_name="ecx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8627,
                color=12,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[4294967261, 4294967280, 4294967288, 4294967293],
                num_micro_executions=5,
                reg_name="eax",
            ),
        ],
        8629: [
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8629,
                color=13,
                size=4,
                use=False,
                new=True,
                count=3,
                dynamic_values=[4294967226, 4294967290, 4294967280, 4294967264],
                num_micro_executions=5,
                reg_name="ecx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8629,
                color=12,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[4294967261, 4294967280, 4294967288, 4294967293],
                num_micro_executions=5,
                reg_name="ecx",
            ),
        ],
        8631: [
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8631,
                color=14,
                size=4,
                use=False,
                new=True,
                count=3,
                dynamic_values=[4294967191, 4294967248, 4294967272, 4294967287],
                num_micro_executions=5,
                reg_name="ecx",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8631,
                color=12,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[4294967261, 4294967280, 4294967288, 4294967293],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8631,
                color=13,
                size=4,
                use=True,
                new=False,
                count=3,
                dynamic_values=[4294967226, 4294967290, 4294967280, 4294967264],
                num_micro_executions=5,
                reg_name="ecx",
            ),
        ],
        8633: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8633,
                color=10,
                size=4,
                use=False,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8633,
                color=10,
                size=4,
                use=True,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                reg_name="edx",
            ),
        ],
        8635: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8635,
                color=11,
                size=4,
                use=False,
                new=False,
                count=1,
                dynamic_values=[255],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="write-def-summary",
                pc=8635,
                color=15,
                size=4,
                use=False,
                new=True,
                count=2,
                dynamic_values=[256],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8635,
                color=10,
                size=4,
                use=True,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                reg_name="eax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8635,
                color=14,
                size=4,
                use=True,
                new=False,
                count=2,
                dynamic_values=[4294967191, 4294967272, 4294967287],
                num_micro_executions=5,
                reg_name="ecx",
            ),
        ],
        8637: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8637,
                color=11,
                size=1,
                use=True,
                new=False,
                count=1,
                dynamic_values=[255],
                num_micro_executions=5,
                reg_name="al",
            )
        ],
        8641: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8641,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8650: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8650,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8655: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8655,
                color=3,
                size=8,
                use=True,
                new=False,
                count=4,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8669: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8669,
                color=3,
                size=8,
                use=True,
                new=False,
                count=4,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8672: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8672,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8682: [
            DynamicRegisterValueSummaryHint(
                message="write-copy-summary",
                pc=8682,
                color=4,
                size=8,
                use=False,
                new=False,
                count=5,
                dynamic_values=[131072, 131073, 131074, 131075],
                num_micro_executions=5,
                reg_name="rax",
            ),
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8682,
                color=4,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[131072],
                num_micro_executions=5,
                reg_name="rax",
            ),
        ],
        8688: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8688,
                color=10,
                size=1,
                use=True,
                new=False,
                count=2,
                dynamic_values=[232, 150, 247],
                num_micro_executions=5,
                reg_name="al",
            )
        ],
        8692: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8692,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8699: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8699,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8703: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8703,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
        8706: [
            DynamicRegisterValueSummaryHint(
                message="read-flow-summary",
                pc=8706,
                color=3,
                size=8,
                use=True,
                new=False,
                count=5,
                dynamic_values=[81912],
                num_micro_executions=5,
                reg_name="rbp",
            )
        ],
    }

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

    correct_derivations = [
        (8735, "rax", set()),
        (
            8604,
            "rax",
            {
                RegisterInfo(
                    color=3, is_new=True, register=RegisterDef(name="rdi", size=8)
                )
            },
        ),
        (
            8688,
            "al",
            {
                MemoryLvalInfo(
                    color=8,
                    is_new=True,
                    bsid=BSIDMemoryReferenceOperand(base="rax"),
                    size=1,
                )
            },
        ),
        (8579, "[rbp-0x18]", set()),
        (8558, "[rbp-0x1c]", set()),
        (
            8568,
            "[rbp-0x20]",
            {
                RegisterInfo(
                    color=4, is_new=True, register=RegisterDef(name="edx", size=4)
                )
            },
        ),
    ]

    for i in range(6):
        (cpc, cvals, cder) = correct_derivations[i]
        (opc, ovals, oder) = derivations[i]
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
