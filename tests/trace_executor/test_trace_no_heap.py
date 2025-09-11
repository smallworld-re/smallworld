from trace_test import check_pcs, test

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    hints = test(100, 12, False, False, False, 1234)
    truth_trace_digest = "89bc64081e73e0414ce7d659a27c67b5"
    res = hints[0].trace_digest == truth_trace_digest
    print(f"Test result: trace_digest matches passed={res}")
