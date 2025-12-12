import tests.integration

testsuites = []
with open(".github/workflows/pull-request.yml", "r") as f:
    for line in f:
        line = line.strip()
        if line.startswith("- testsuite: "):
            testsuites.append(line[13:])

panda_tests = []
for classname in testsuites:
    cls = getattr(tests.integration, classname)
    for method in dir(cls):
        if "panda" in method:
            panda_tests.append(f"{classname}.{method}")


with open("run_panda_tests.sh", "w") as f:
    print("#!/bin/sh", file=f)
    print("set -e", file=f)
    print("set -x", file=f)
    for test in panda_tests:
        print("python3 tests/integration.py " + test, file=f)
