import re
import logging

from mcrit.server.utils import timing, jsonify
from mcrit.index.MinHashIndex import MinHashIndex


LOGGER = logging.getLogger(__name__)


class BlocksResource:
    def __init__(self, index: MinHashIndex):
        self.index = index

    @timing
    def on_get_unique_blocks_for_family(self, req, resp, family_id=None):
        LOGGER.info("BlocksResource.on_get_unique_blocks_for_family")
        unique_blocks = {}
        # TODO get samples for family_id
        target_sample_ids = []
        unique_blocks = self.index.getUniqueBlocks(target_sample_ids)
        resp.data = jsonify({"status": "successful", "data": unique_blocks})

    @timing
    def on_get_unique_blocks_for_samples(self, req, resp, comma_separated_sample_ids=None):
        LOGGER.info("BlocksResource.on_get_unique_blocks")
        unique_blocks = {}
        if re.match("^\d+(?:[\s]*,[\s]*\d+)*$", comma_separated_sample_ids):
            target_sample_ids = [int(sample_id) for sample_id in comma_separated_sample_ids.split(",")]
            unique_blocks = self.index.getUniqueBlocks(target_sample_ids)
        resp.data = jsonify({"status": "successful", "data": unique_blocks})