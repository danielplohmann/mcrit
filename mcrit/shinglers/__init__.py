"""Shingler implementations for MCRIT.

This directory is intentionally a package so that setuptools' ``find_packages``
ships these modules with the distribution. The shinglers are loaded at runtime
by ``mcrit.minhash.ShingleLoader`` via ``sys.path``-based imports, which is
unaffected by this package marker.
"""