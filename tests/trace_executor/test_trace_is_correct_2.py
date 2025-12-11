from trace_test import test

if __name__ == "__main__":
    # this trace should trigger a memory error since there's no heap
    # it won't do much
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

    truth_trace_digest = "4e0e389df50db70d914d7a8f796de9e6"
    expected(
        hints[0].trace_digest == truth_trace_digest,
        "trace digest matchest truth",
        "trace digest does not match truth",
    )

    expected(
        len(hints[0].trace) == 100,
        "trace is 100 instructions which is correct",
        f"trace is {len(hints[0].trace)} which is incorrect",
    )

    expected(
        hints[0].exception is None,
        "no exception in trace as expected",
        f"exception in trace {type(hints[0].exception)} is incorrect",
    )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
