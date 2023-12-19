from setuptools import find_packages, setup

import smallworld

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="smallworld",
    version=smallworld.__version__,
    author=smallworld.__author__,
    author_email="smallworld@ll.mit.edu",
    url="https://github.com/smallworld-re/smallworld",
    description=smallworld.__description__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    license_files=["LICENSE.txt"],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["unicorn", "angr", "capstone"],
    extras_require={
        "development": [
            "black",
            "isort",
            "flake8",
            "mypy",
            "pip-tools",
            "pre-commit",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["smallworld = smallworld.__main__:main"]},
)
