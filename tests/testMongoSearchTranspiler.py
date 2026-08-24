import unittest

from mcrit.index.SearchCursor import FullSearchCursor
from mcrit.index.SearchQueryTree import SearchConditionNode
from mcrit.storage.MongoDbStorage import MongoDbStorage, MongoSearchTranspiler


class TestMongoSearchTranspiler(unittest.TestCase):
    def _visit(self, field, operator, value):
        return MongoSearchTranspiler().visit(SearchConditionNode(field, operator, value))

    def test_pichash_equality_is_encoded(self):
        # pichashes are stored hex-encoded in the "_pichash" field
        self.assertEqual(self._visit("pichash", "=", "0x1234"), {"_pichash": "0x1234"})

    def test_pichash_inequality_is_encoded(self):
        self.assertEqual(self._visit("pichash", "!=", "0x1234"), {"_pichash": {"$ne": "0x1234"}})

    def test_pichash_decimal_value_is_encoded_as_hex(self):
        self.assertEqual(self._visit("pichash", "=", "4660"), {"_pichash": "0x1234"})

    def test_pichash_range_operators_are_rejected(self):
        for operator in ("<", "<=", ">", ">="):
            with self.assertRaises(ValueError):
                self._visit("pichash", operator, "0x1234")

    def test_pichash_substring_search_matches_the_encoded_field(self):
        # "?" produces a regex, which cannot be hex-encoded (and used to raise a TypeError here),
        # so it is matched against the stored representation and only the field gets renamed
        condition = self._visit("pichash", "?", "1234")
        self.assertEqual(["_pichash"], list(condition))
        self.assertTrue(condition["_pichash"].search("0x1234"))
        self.assertIsNone(condition["_pichash"].search("0x5678"))

    def test_pichash_negated_substring_search_matches_the_encoded_field(self):
        condition = self._visit("pichash", "!?", "1234")
        self.assertEqual(["_pichash"], list(condition))
        self.assertEqual(["$not"], list(condition["_pichash"]))
        self.assertTrue(condition["_pichash"]["$not"].search("0x1234"))

    def test_other_fields_are_untouched(self):
        self.assertEqual(self._visit("num_functions", ">", "5"), {"num_functions": {"$gt": 5}})
        self.assertEqual(self._visit("family", "=", "somefamily"), {"family": "somefamily"})


class TestMongoSortableFields(unittest.TestCase):
    def _cursor(self, *sort_fields):
        return FullSearchCursor(None, [(field, True) for field in sort_fields])

    def test_pichash_cannot_be_sorted_by(self):
        # the cursor pages by comparing the sort field, which the hex-encoded pichash does not allow
        with self.assertRaises(ValueError):
            MongoDbStorage._assert_sortable_fields(self._cursor("pichash", "function_id"))

    def test_regular_fields_can_be_sorted_by(self):
        MongoDbStorage._assert_sortable_fields(None)
        MongoDbStorage._assert_sortable_fields(self._cursor("function_id"))
        MongoDbStorage._assert_sortable_fields(self._cursor("function_name", "function_id"))


if __name__ == "__main__":
    unittest.main()
