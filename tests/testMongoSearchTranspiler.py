import unittest

from mcrit.index.SearchQueryTree import SearchConditionNode
from mcrit.storage.MongoDbStorage import MongoSearchTranspiler


class TestMongoSearchTranspiler(unittest.TestCase):
    def _visit(self, field, operator, value):
        return MongoSearchTranspiler().visit(SearchConditionNode(field, operator, value))

    def test_pichash_equality_is_encoded(self):
        # pichashes are stored hex-encoded in the "_pichash" field
        self.assertEqual(self._visit("pichash", "=", "0x1234"), {"_pichash": "0x1234"})

    def test_pichash_inequality_is_encoded(self):
        self.assertEqual(self._visit("pichash", "!=", "0x1234"), {"_pichash": {"$ne": "0x1234"}})

    def test_pichash_range_operators_are_rejected(self):
        for operator in ("<", "<=", ">", ">="):
            with self.assertRaises(ValueError):
                self._visit("pichash", operator, "0x1234")

    def test_other_fields_are_untouched(self):
        self.assertEqual(self._visit("num_functions", ">", "5"), {"num_functions": {"$gt": 5}})
        self.assertEqual(self._visit("family", "=", "somefamily"), {"family": "somefamily"})


if __name__ == "__main__":
    unittest.main()
