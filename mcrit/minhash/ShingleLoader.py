#!/usr/bin/env python3

import logging
import os
import random
import sys

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class ShingleLoader:

    WEIGHT_STRATEGY_ALL_SHINGLERS_EQUAL = 1
    WEIGHT_STRATEGY_SHINGLER_WEIGHTS = 2

    def __init__(self, shingler_config):
        self._config = shingler_config
        self._python_files = self._getPythonFiles()
        self._shingler_classes = self._getShinglerClasses()
        self._updateXorValues()

    def _updateXorValues(self):
        if not self._config.SHINGLERS_XOR_VALUES:
            random.seed(self._config.SHINGLERS_SEED)
            self._config.SHINGLERS_XOR_VALUES = [0] + [
                random.randint(0, 0xFFFFFFFF) for _ in range(max(self._config.SHINGLERS_WEIGHTS.values()))
            ]

    def getShinglers(self):
        """Get a (name-)sorted list of shinglers as specified in the config"""
        if self._config.SHINGLER_WEIGHT_STRATEGY == self.WEIGHT_STRATEGY_SHINGLER_WEIGHTS:
            return self._initWeightedShinglers()
        elif self._config.SHINGLER_WEIGHT_STRATEGY == self.WEIGHT_STRATEGY_ALL_SHINGLERS_EQUAL:
            return self._initAllShinglers()
        raise NotImplementedError("Unknown Shingler Weight Strategy.")

    def _initWeightedShinglers(self):
        shingler_instances = []
        for shingler_cls in self._shingler_classes:
            shingler_name = shingler_cls(self._config).getName()
            if shingler_name in self._config.SHINGLERS_WEIGHTS and self._config.SHINGLERS_WEIGHTS[shingler_name]:
                weight = self._config.SHINGLERS_WEIGHTS[shingler_name]
                shingler = shingler_cls(self._config, weight)
                shingler_instances.append(shingler)
        LOGGER.info(
            "Using Shingler Setup: %s",
            ", ".join(
                sorted(["%s (%d)" % (shingler.getName(), shingler.getWeight()) for shingler in shingler_instances])
            ),
        )
        return sorted(shingler_instances)

    def _initAllShinglers(self):
        return sorted([shingler_cls(self._config) for shingler_cls in self._shingler_classes])

    def _getPythonFiles(self):
        python_files = [
            os.path.join(self._config.SHINGLER_DIR, candidate_file)
            for candidate_file in os.listdir(self._config.SHINGLER_DIR)
            if (
                os.path.isfile(os.path.join(self._config.SHINGLER_DIR, candidate_file))
                and candidate_file.endswith("Shingler.py")
                and candidate_file != "AbstractShingler.py"
            )
        ]
        return python_files

    def _getShinglerClasses(self):
        classes = []
        for python_file in sorted(self._python_files):
            file_path = os.path.split(os.path.abspath(python_file))[0]
            if file_path not in sys.path:
                sys.path.append(file_path)
            python_module = (os.path.split(python_file)[1])[:-3]
            LOGGER.info("loading shingler module: %s", python_module)
            module = __import__(python_module, fromlist=[python_module])
            module_class = getattr(module, python_module)
            classes.append(module_class)
        return classes
