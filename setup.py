from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

# AFAIK, there is no way to load a constraints file directly.
# Hey look I just made one.
immediate_dependencies = {
    "angr",
    "capstone",
    "lief",
    "pyhidra",
    "pypcode",
    "unicorn",
}
# For some reason, pyhidra doesn't show up on pip-compile
install_requires = ["pyhidra==1.3.0"]
with open("constraints.txt", "r") as f:
    constraints = f.read().split("\n")
    for c in filter(
        lambda x: not x.startswith("#"), map(lambda x: x.strip(), constraints)
    ):
        package = c.split("=", 1)[0]
        if package in immediate_dependencies:
            install_requires.append(c)

if len(install_requires) != len(immediate_dependencies):
    print(install_requires)
    print(immediate_dependencies)
    raise ValueError("Missing constraints for some packages")

setup(
    name="smallworld-re",
    version="1.0.4",
    author="MIT Lincoln Laboratory",
    author_email="smallworld@ll.mit.edu",
    url="https://github.com/smallworld-re/smallworld",
    description="An emulation stack tracking library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    license_files=["LICENSE.txt"],
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=install_requires,
    extras_require={
        "development": [
            "black",
            "isort",
            "flake8",
            "mypy",
            "pip-tools",
            "pre-commit",
            "sphinx",
            "sphinxcontrib-programoutput",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["smallworld = smallworld.__main__:main"]},
)
