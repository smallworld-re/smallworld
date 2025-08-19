from trace_test import test

from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.instructions.instructions import RegisterOperand

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    hints = test(100, 12, False, False, False, 1234)
    if len(hints) == 0 or len(hints) > 1:
        print("Did not get 1 hint which is wrong")
    else:
        branches = 0
        cmps = {
            0x21A2: [
                ("Register", RegisterOperand("rbp"), 81912),
                (
                    "BSIDMemoryReference",
                    BSIDMemoryReferenceOperand("rbp", None, 1, -0x1C),
                    b"\x0c\x00\x00\x00",
                ),
            ],
            0x21AC: [
                ("Register", RegisterOperand("rbp"), 81912),
                (
                    "BSIDMemoryReference",
                    BSIDMemoryReferenceOperand("rbp", None, 1, -0x20),
                    b"\x00\x00\x00\x00",
                ),
            ],
            0x2236: [
                ("Register", RegisterOperand("eax"), 0),
                ("Register", RegisterOperand("rbp"), 81912),
                (
                    "BSIDMemoryReference",
                    BSIDMemoryReferenceOperand("rbp", None, 1, -0x1C),
                    b"\x0c\x00\x00\x00",
                ),
            ],
        }
        immediates = {0x21A2: [12], 0x21AC: [0]}

        def expected(cond, msg):
            if cond:
                print("EXPECTED   ", end="")
            else:
                print("UNEXPECTED ", end="")
            print(msg)

        def cmp_in_cmps(pc, c1, cmps):
            for pc2, c2 in cmps.items():
                if pc == pc2 and (len(c1) == len(c2)):
                    num_matches = 0
                    for e1 in c1:
                        found = False
                        for e2 in c2:
                            if e1 == e2:
                                found = True
                                num_matches += 1
                        expected(found, f"cmp part {pc:x} {e1}")
                    if num_matches == len(c1):
                        # found all parts of c1 in c2. done
                        return True
            return False

        for te in hints[0].trace:
            if te.branch:
                branches += 1
            if len(te.cmp) > 0:
                cmp_in_cmps(te.pc, te.cmp, cmps)
            #                         f"cmp {te.pc:x} {te.cmp}")
            if len(te.immediates) > 0:
                expected(
                    te.pc in immediates and immediates[te.pc] == te.immediates,
                    f"immediate {te.pc:x} {te.immediates}",
                )
        expected(branches == 3, f"num_branches = {branches}")

    # breakpoint()
    # pcs = [te.pc for te in hints[0].trace]
    # truth_pcs = [0x2189, 0x218d, 0x218e, 0x2191, 0x2195, 0x2198, 0x219b, 0x21a2, 0x21a6, 0x21ac, 0x21b0, 0x21ba, 0x21c1, 0x2233, 0x2236, 0x2239, 0x21c3, 0x21c6, 0x21c9, 0x21cd, 0x21d0]
    # res = check_pcs(pcs, truth_pcs, "observed", "truth")
    # print(f"Test result: passed={res}")
