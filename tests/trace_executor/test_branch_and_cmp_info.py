from trace_test import test

from smallworld.instructions.bsid import BSIDMemoryReferenceOperand
from smallworld.instructions.instructions import RegisterOperand

if __name__ == "__main__":
    # test(num_insn, buflen, create_heap, fortytwos, randomize_regs, seed):
    hints = test(100, 12, False, False, False, 1234)
    truth_trace_digest = "89bc64081e73e0414ce7d659a27c67b5"
    res = hints[0].trace_digest == truth_trace_digest
    print(f"Test result: trace_digest matches passed={res}")
 
    
    #                               TraceElement(pc=8610, ic=7, mnemonic='cmp', op_str='dword ptr [rbp - 0x1c], 0xc',
    #                                            cmp=[BSIDMemoryReferenceOperand(rbp+-1c), 12], branch=False, immediates=[12]),
    #                               TraceElement(pc=8620, ic=9, mnemonic='cmp', op_str='dword ptr [rbp - 0x20], 0',
    #                                            cmp=[BSIDMemoryReferenceOperand(rbp+-20), 0], branch=False, immediates=[0]),
    #                               TraceElement(pc=8758, ic=14, mnemonic='cmp', op_str='dword ptr [rbp - 0x1c], eax',
    #                                            cmp=[BSIDMemoryReferenceOperand(rbp+-1c), RegisterOperand(eax)], branch=False, immediates=[]),
    #                               ],

    if len(hints) == 0 or len(hints) > 1:
        print("Did not get 1 hint which is wrong")
    else:
        truth_cmps = {
            0x21A2: [
                BSIDMemoryReferenceOperand("rbp", None, 1, -0x1c), 12
            ],
            0x21AC: [
                BSIDMemoryReferenceOperand("rbp", None, 1, -0x20), 0
            ],
            0x2236: [                
                BSIDMemoryReferenceOperand("rbp", None, 1, -0x1C),
                RegisterOperand("eax")
            ],
        }
        truth_immediates = {0x21A2: [12], 0x21AC: [0]}
        truth_branches = 3

        def expected(cond, msg):
            if cond:
                print("EXPECTED   ", end="")
            else:
                print("UNEXPECTED ", end="")
            print(msg)


        branches = 0
        for te in hints[0].trace:
            if te.branch:
                branches += 1
            if len(te.cmp) > 0:
                expected(te.pc in truth_cmps and \
                         te.cmp == truth_cmps[te.pc], f"cmps match for pc={te.pc:x}")
            if len(te.immediates) > 0:
                expected(te.pc in truth_immediates and \
                         te.immediates == truth_immediates[te.pc], f"immediates match for pc={te.pc:x}")
                
        expected(branches == truth_branches, f"num_branches = {branches}")

    # breakpoint()
    # pcs = [te.pc for te in hints[0].trace]
    # truth_pcs = [0x2189, 0x218d, 0x218e, 0x2191, 0x2195, 0x2198, 0x219b, 0x21a2, 0x21a6, 0x21ac, 0x21b0, 0x21ba, 0x21c1, 0x2233, 0x2236, 0x2239, 0x21c3, 0x21c6, 0x21c9, 0x21cd, 0x21d0]
    # res = check_pcs(pcs, truth_pcs, "observed", "truth")
    # print(f"Test result: passed={res}")
