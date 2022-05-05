import hashlib
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Dict

from mcrit.config.ConfigInterface import ConfigInterface, default_field
from mcrit.minhash.ShingleLoader import ShingleLoader


@dataclass
class ShinglerConfig(ConfigInterface):

    THIS_FILE_PATH: str = str(os.path.abspath(__file__))
    PROJECT_ROOT: str = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))

    # Directory in which to search for files matching pattern "*Shingler.py"
    SHINGLER_DIR: str = str(os.path.abspath(os.sep.join([PROJECT_ROOT, "shinglers"])))
    # Application of Shinglers can be influenced by weights, effectively running the same instance multiple times (increasing their "chance")
    SHINGLER_WEIGHT_STRATEGY: ... = ShingleLoader.WEIGHT_STRATEGY_SHINGLER_WEIGHTS
    # the expected range for logbucket matching
    SHINGLER_LOGBUCKETS: int = 100000
    # number of values to put in the range left and right
    SHINGLER_LOGBUCKET_RANGE: int = 1
    # add additional counts for values further to the center
    SHINGLER_LOGBUCKET_CENTERED: bool = True
    # The weights to use for the above described method
    SHINGLERS_WEIGHTS: ... = default_field(
        {"FuzzyStatPairShingler": 1, "EscapedBlockShingler": 3}
    )
    # random seed to be used when initiating XOR values for shingler hash seeds
    SHINGLERS_SEED: int = 0xDEADBEEF
    # will be set automatically when shinglers are loaded (listed here for completeness)
    SHINGLERS_XOR_VALUES: ... = default_field([])

    def getConfigHash(self):
        config_str = ""
        config_str += f"_{self.SHINGLER_WEIGHT_STRATEGY}_{self.SHINGLER_LOGBUCKETS}_{self.SHINGLER_LOGBUCKET_RANGE}_{self.SHINGLER_LOGBUCKET_CENTERED}"
        config_str += f"_{','.join(['%s-%s' % (k, v) for k, v in sorted(self.SHINGLERS_WEIGHTS.items())])}"
        config_str += f"_{self.SHINGLERS_SEED}"
        return hashlib.sha256(config_str.encode('utf-8')).hexdigest()
