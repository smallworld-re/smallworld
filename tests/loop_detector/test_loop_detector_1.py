from loop_detector_test import test

from smallworld.hinting import Hinter, LoopHint

if __name__ == "__main__":

    # these two traces should hit *both* loops
    hinter = Hinter()
    hints1 = test(hinter, 200, 40, True, True, True, 1234)
    hints2 = test(hinter, 200, 47, True, True, True, 1234)

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
        type(hints1[-1]) is LoopHint,
        "found loop hint in hints1",
        "loop hint not found in hints1",
    )
    expected(
        type(hints2[-1]) is LoopHint,
        "found loop hint in hints2",
        "loop hint not found in hints2",
    )

    expected(
        hints1[-1]
        == LoopHint(
            message="loop head and strands detected",
            head=8722,
            strands=[
                [
                    8722,
                    8725,
                    8728,
                    8732,
                    8735,
                    8738,
                    8743,
                    8745,
                    8747,
                    8751,
                    8754,
                    8756,
                    8759,
                    8761,
                    8763,
                    8766,
                    8768,
                    8770,
                    8772,
                    8775,
                    8778,
                    8782,
                    8785,
                    8788,
                    8722,
                ],
            ],
        ),
        "loop hint in hints1 is correct",
        "loop hint in hints1 is not correct",
    )

    expected(
        hints2[-1]
        == LoopHint(
            message="loop head and strands detected",
            head=8591,
            strands=[
                [
                    8591,
                    8594,
                    8597,
                    8601,
                    8604,
                    8607,
                    8612,
                    8614,
                    8616,
                    8620,
                    8622,
                    8625,
                    8627,
                    8629,
                    8631,
                    8633,
                    8635,
                    8637,
                    8639,
                    8655,
                    8658,
                    8660,
                    8663,
                    8665,
                    8667,
                    8669,
                    8672,
                    8675,
                    8678,
                    8682,
                    8685,
                    8688,
                    8690,
                    8699,
                    8703,
                    8706,
                    8709,
                    8591,
                ],
                [
                    8591,
                    8594,
                    8597,
                    8601,
                    8604,
                    8607,
                    8612,
                    8614,
                    8616,
                    8620,
                    8622,
                    8625,
                    8627,
                    8629,
                    8631,
                    8633,
                    8635,
                    8637,
                    8639,
                    8641,
                    8644,
                    8646,
                    8648,
                    8650,
                    8653,
                    8672,
                    8675,
                    8678,
                    8682,
                    8685,
                    8688,
                    8690,
                    8699,
                    8703,
                    8706,
                    8709,
                    8591,
                ],
                [
                    8591,
                    8594,
                    8597,
                    8601,
                    8604,
                    8607,
                    8612,
                    8614,
                    8616,
                    8620,
                    8622,
                    8625,
                    8627,
                    8629,
                    8631,
                    8633,
                    8635,
                    8637,
                    8639,
                    8641,
                    8644,
                    8646,
                    8648,
                    8650,
                    8653,
                    8672,
                    8675,
                    8678,
                    8682,
                    8685,
                    8688,
                    8690,
                    8692,
                    8699,
                    8703,
                    8706,
                    8709,
                    8591,
                ],
            ],
        ),
        "loop hint in hints2 is correct",
        "loop hint in hints2 is not correct",
    )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
