# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

with open("README.md") as f:
    README = f.read()

setup(
    name='mcrit',
    version="1.4.1",
    description='MCRIT is a framework created for simplified application of the MinHash algorithm to code similarity.',
    long_description_content_type="text/markdown",
    long_description=README,
    author='Daniel Plohmann, Manuel Blatt, Steffen Enders, Paul Hordiienko',
    author_email='daniel.plohmann@fkie.fraunhofer.de',
    url='https://github.com/danielplohmann/mcrit',
    license="NU General Public License v3 (GPLv3)",
    packages=find_packages(exclude=("tests", "data", "docs", "examples", "plugins")),
    install_requires=open("requirements.txt").read().splitlines(),
    data_files=[
        ("", ["LICENSE", "requirements.txt"]),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
    entry_points={
        'console_scripts': [
            'mcrit=mcrit.__main__:main'
        ]
    },
)
