from trace_test import test

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):

    # we should get same trace from these two invocations
    hints1 = test(100, 47, True, True, True, 1234)
    hints2 = test(100, 47, True, True, True, 1234)

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

    expected(
        hints1[0].trace_digest == hints2[0].trace_digest,
        "trace digests are same",
        "trace digests are not the same",
    )

    expected(
        len(hints1[0].trace) == len(hints2[0].trace),
        "traces are same number of instructions",
        "traces are not same number of instructions",
    )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
