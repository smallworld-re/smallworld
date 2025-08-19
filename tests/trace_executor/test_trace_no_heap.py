from trace_test import check_pcs, test

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    hints = test(100, 12, False, False, False, 1234)
    pcs = [te.pc for te in hints[0].trace]
    truth_pcs = [
        0x2189,
        0x218D,
        0x218E,
        0x2191,
        0x2195,
        0x2198,
        0x219B,
        0x21A2,
        0x21A6,
        0x21AC,
        0x21B0,
        0x21BA,
        0x21C1,
        0x2233,
        0x2236,
        0x2239,
        0x21C3,
        0x21C6,
        0x21C9,
        0x21CD,
        0x21D0,
    ]
    res = check_pcs(pcs, truth_pcs, "observed", "truth")
    print(f"Test result: passed={res}")
