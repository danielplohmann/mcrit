# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

with open("README.md") as f:
    README = f.read()

requirements = [
    "dataclasses",
    "falcon>=2.0.0",
    "fastcluster",
    "mmh3>=2.5.1",
    "numpy",
    "picblocks>=1.1.2",
    "pymongo",
    "pyparsing>=3",
    "requests",
    "scipy",
    "smda>=1.3.0",
    "tqdm",
    "waitress",
]

setup(
    name='mcrit',
    version="0.20.1",
    description='MCRIT is a framework created for simplified application of the MinHash algorithm to code similarity.',
    long_description_content_type="text/markdown",
    long_description=README,
    author='Daniel Plohmann, Steffen Enders, Paul Hordiienko, Manuel Blatt',
    author_email='daniel.plohmann@fkie.fraunhofer.de',
    url='https://github.com/danielplohmann/mcrit',
    license="NU General Public License v3 (GPLv3)",
    packages=find_packages(exclude=("tests", "data", "docs", "examples", "plugins")),
    install_requires=requirements,
    data_files=[
        ("", ["LICENSE"]),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
)
