from trace_test import test

import smallworld
from smallworld.instructions.bsid import x86BSIDMemoryReferenceOperand

if __name__ == "__main__":
    # this trace should trigger a memory error since there's no heap
    # it won't do much
    hints = test(
        100,    # max number of instructions
        46,     # buffer length (47 is a magic length, unlocking ad ifferent code path)
        False,  # if true, we create a heap before initializing
        False,  # [only does something if create_heap is true) if true,
                # we add lots of 0x42 to the buffer
        False,  # if true we randomize registers and buffers, else they are all zero
        1234,   # random seed
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

    truth_trace_digest = "f88af528a6119e62d1f9a790a8321110"
    expected(
        hints[0].trace_digest == truth_trace_digest,
        "trace digest matchest truth",
        "trace digest does not match truth",
    )

    expected(
        len(hints[0].trace) == 18,
        "trace is 18 instructions which is correct",
        f"trace is {len(hints[0].trace)} which is incorrect",
    )

    expected_args = ("Quit emulation due to read of unmapped memory", 8735)
    expected(
        hints[0].exception.args == expected_args,
        "execption args are what we expect",
        "execption args are incorrect",
    )

    expected(
        type(hints[0].exception) is smallworld.exceptions.EmulationReadUnmappedFailure,
        "exception type is correct -- EmulationReadUnmappedFailure",
        f"exception type is incorrect -- {type(hints[0].exception)}",
    )

    expected(
        hints[0].exception.operands == [(x86BSIDMemoryReferenceOperand(base="rax"), 0)],
        f"exception operands are correct -- {hints[0].exception.operands}",
        f"exception operands are incorrect -- {hints[0].exception.operands}",
    )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
