# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

with open("README.md") as f:
    README = f.read()

setup(
    name="mcrit",
    version="1.7.1",
    description="MCRIT is a framework created for simplified application of the MinHash algorithm to code similarity.",
    long_description_content_type="text/markdown",
    long_description=README,
    author="Daniel Plohmann, Manuel Blatt, Steffen Enders, Paul Hordiienko",
    author_email="daniel.plohmann@fkie.fraunhofer.de",
    url="https://github.com/danielplohmann/mcrit",
    license="GPL-3.0-only",
    packages=find_packages(exclude=("tests", "data", "docs", "examples", "plugins")),
    package_data={"mcrit": ["cache/*.json"]},
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.11",
    data_files=[
        ("", ["LICENSE", "requirements.txt"]),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
    entry_points={"console_scripts": ["mcrit=mcrit.__main__:main"]},
)
