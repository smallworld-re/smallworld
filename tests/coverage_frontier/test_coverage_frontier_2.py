from coverage_frontier_test import test

if __name__ == "__main__":
    # 1 microexecution
    # 100 max num instructions
    # 1233 is random seed
    hints = test(3, 100, 1233)

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

    h = hints[0]
    expected(
        len(h.coverage_frontier) == 0,
        "Zero items in coverage frontier, as expected",
        f"{len(h.coverage_frontier)} branches in coverage frontier, which is incorrect",
    )

    expected(
        num_unexpected == 0,
        "No unexpected results",
        f"{num_unexpected} unexpected results",
    )
