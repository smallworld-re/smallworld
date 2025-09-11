from trace_test import check_pcs, test

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    hints = test(100, 13, True, False, False, 1234)
    truth_trace_digest = "159c8bf27e774308003eee85235dd34b"
    res = hints[0].trace_digest == truth_trace_digest
    print(f"Test result: trace_digest matches passed={res}")
