import os
import sys

# Shinglers use bare module imports (e.g. `from AbstractShingler import ...`) which
# only resolve when the shinglers package directory is on sys.path. MCRIT adds it
# at load time (see mcrit/minhash/ShingleLoader._getShinglerClasses); replicate that
# here so tests can import shingler modules directly.
_SHINGLER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mcrit", "shinglers")
if os.path.abspath(_SHINGLER_DIR) not in [os.path.abspath(p) for p in sys.path]:
    sys.path.insert(0, os.path.abspath(_SHINGLER_DIR))
