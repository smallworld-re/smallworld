from trace_test import test

from smallworld.instructions.bsid import x86BSIDMemoryReferenceOperand
from smallworld.instructions.instructions import RegisterOperand

if __name__ == "__main__":
    hints = test(
        100,  # number of instructions
        47,  # buffer length (47 is a magic length, unlocking ad ifferent code path)
        True,  # if true, we create a heap before initializing
        True,  # [only does something if create_heap is true) if true, we add lots of 0x42 to the buffer
        True,  # if true we randomize registers and buffers, else they are all zero
        1234,  # random seed
    )

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
        len(hints) == 1,
        "One hint returned, as expected",
        f"{len(hints)} hints returned, which is incorrect",
    )

    branches = 0

    obs_cmps = []
    obs_imms = []
    for te in hints[0].trace:
        if te.branch:
            branches += 1
        if len(te.cmp) > 0:
            obs_cmps.append((te.pc, te.cmp))
        if len(te.immediates) > 0:
            obs_imms.append((te.pc, te.immediates))

    expected(
        branches == 9,
        "num branches is 9, as expected",
        f"num branches is {branches} but is supposed to be 9",
    )

    truth_cmps = [
        (8558, [x86BSIDMemoryReferenceOperand(base="rbp", offset=-0x1C), 47]),
        (8568, [x86BSIDMemoryReferenceOperand(base="rbp", offset=-0x20), 0]),
        (
            8706,
            [
                RegisterOperand("eax"),
                x86BSIDMemoryReferenceOperand(base="rbp", offset=-0x1C),
            ],
        ),
        (8637, [RegisterOperand("al"), RegisterOperand("al")]),
        (8688, [RegisterOperand("al"), 42]),
        (
            8706,
            [
                RegisterOperand("eax"),
                x86BSIDMemoryReferenceOperand(base="rbp", offset=-0x1C),
            ],
        ),
        (8637, [RegisterOperand("al"), RegisterOperand("al")]),
        (8688, [RegisterOperand("al"), 42]),
        (
            8706,
            [
                RegisterOperand("eax"),
                x86BSIDMemoryReferenceOperand(base="rbp", offset=-0x1C),
            ],
        ),
    ]

    truth_imms = [(8558, [47]), (8568, [0]), (8688, [42]), (8688, [42])]

    def list_diff(tl, ol):
        if len(tl) != len(ol):
            print("truth and obs Lists are different lengths")
        # breakpoint()
        for i in range(0, max(len(tl), len(ol))):
            te = None
            oe = None
            if i < len(tl):
                te = tl[i]
            if i < len(ol):
                oe = ol[i]
            if te == oe:
                print(f"{i} SAME {te}")
            else:
                print(f"{i} DIFF TRUTH={te} OBS={oe}")
                break

    if not expected(
        truth_cmps == obs_cmps,
        "comparisons in trace are correct",
        "comparisons in trace are not correct",
    ):
        list_diff(truth_cmps, obs_cmps)

    if not expected(
        truth_imms == obs_imms,
        "immediates in trace are correct",
        "immediates in trace are not correct",
    ):
        list_diff(truth_imms, obs_imms)

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
