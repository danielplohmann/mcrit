from timeit import default_timer as timer
from bson import json_util
import logging

LOGGER = logging.getLogger(__name__)


def getMatchingParams(req_params):
    parameters = {}
    for key, value in req_params.items():
        try:
            if key == "pichash_size":
                pichash_size = int(value)
                pichash_size = max(0, pichash_size)
                parameters["pichash_size"] = pichash_size
                # self.index.updatePicHashSize(pichash_size)
            if key == "minhash_score":
                minhash_score = int(value)
                minhash_score = max(0, min(100, minhash_score))
                parameters["minhash_threshold"] = minhash_score
            if key == "force_recalculation":
                if value.lower() == "true":
                    parameters["force_recalculation"] = True
            if key == "band_matches_required":
                band_matches_required = int(value)
                band_matches_required = max(0, band_matches_required)
                parameters["band_matches_required"] = band_matches_required
        except:
            LOGGER.warning(f"Failed to handle request parameter: {key}: {value}")
    return parameters


def jsonify(content, debug_print=False):
    if debug_print:
        print(content)
        print(json_util.dumps(content).encode("utf-8"))
    return json_util.dumps(content).encode("utf-8")


def timing(func):
    def wrapper(*args, **kwargs):
        start = timer()
        func(*args, **kwargs)
        end = timer()
        LOGGER.info("  *** this took: %s sec" % (end - start))

    return wrapper
