from trace_test import check_pcs, test

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):

    # we should get same trace from these two invocations
    hints1 = test(100, 12, True, True, True, 1234)
    hints2 = test(100, 12, True, True, True, 12345)
    assert len(hints1) == len(hints2)
    assert len(hints1) == 1
    pcs1 = [te.pc for te in hints1[0].trace]
    pcs2 = [te.pc for te in hints2[0].trace]
    res = check_pcs(pcs1, pcs2, "version1", "version2")
    print(f"Test result: passed={res}")
