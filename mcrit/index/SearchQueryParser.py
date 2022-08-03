from string import whitespace
from pyparsing import (
    Word,
    CharsNotIn,
    Group,
    ZeroOrMore,
    QuotedString,
    oneOf,
    Suppress,
    identchars,
    identbodychars
)

from mcrit.index.SearchQueryTree import SearchConditionNode, SearchTermNode

class SearchQueryParser:
    def __init__(self):
        self._parser = self._get_parser()
    
    def _get_parser(self):
        search_term = QuotedString('"', esc_char="\\", esc_quote='\\"') \
            | QuotedString("'", esc_char="\\", esc_quote="\\'") \
            | ZeroOrMore(Suppress(whitespace))+CharsNotIn(whitespace) 
        identifier = Word(identchars, identbodychars+".")
        operator = oneOf("< <= > >= =")
        condition_compare = identifier + (":" + operator + search_term).leave_whitespace()
        condition_equal = identifier + (":" + search_term).leave_whitespace()
        one_filter = condition_compare | condition_equal | search_term
        parser = ZeroOrMore(Group(one_filter))
        return parser
    
    def parse(self, string):
        raw_result = self._parser.parse_string(string)
        interpreted_result = []
        for part in raw_result:
            if len(part) == 1:
                interpreted_result.append(SearchTermNode(part[0]))
            if len(part) == 3:
                interpreted_result.append(SearchConditionNode(part[0], "", part[-1]))
            if len(part) == 4:
                interpreted_result.append(SearchConditionNode(part[0], part[-2], part[-1]))
        return interpreted_result