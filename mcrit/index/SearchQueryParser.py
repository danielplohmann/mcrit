from functools import lru_cache
from string import whitespace
from pyparsing import (
    Word,
    CharsNotIn,
    CharsNotIn,
    Group,
    ZeroOrMore,
    OneOrMore,
    QuotedString,
    oneOf,
    Suppress,
    identchars,
    identbodychars,
    Forward,
    Keyword,
    StringEnd,
)

from mcrit.index.SearchQueryTree import Node, AndNode, NotNode, OrNode, SearchConditionNode, SearchTermNode

class SearchQueryParser:
    def __init__(self):
        self._parser = self._get_parser()
    
    def _get_parser(self):
        search_term = QuotedString('"', esc_char="\\", esc_quote='\\"') \
            | QuotedString("'", esc_char="\\", esc_quote="\\'") \
            | ZeroOrMore(Suppress(whitespace))+CharsNotIn(whitespace+"()")
        identifier = Word(identchars, identbodychars+".")
        operator = oneOf("< <= > >= = != ? !?")
        condition_compare = identifier + (":" + operator + search_term).leave_whitespace()
        condition_equal = identifier + (":" + search_term).leave_whitespace()
        one_filter = condition_compare | condition_equal | search_term
        one_filter.setParseAction(self._one_filter_action)

        operatorOr = Forward()

        operatorParenthesis = (
            Group(Suppress("(") + operatorOr + Suppress(")"))
        ) | one_filter

        operatorParenthesis.setParseAction(self._parenthesis_action)

        operatorNot = Forward()
        operatorNot << (
            Group(Suppress(Keyword("NOT")) + operatorNot)
            | operatorParenthesis
        )

        operatorNot.setParseAction(self._not_action)

        operatorAnd = Forward()
        operatorAnd << (
            Group(
                operatorNot + Suppress(Keyword("AND")) + operatorAnd
            )
            | Group(
                operatorNot + OneOrMore(~oneOf("AND OR") + operatorAnd)
            )
            | operatorNot
        )
        operatorAnd.setParseAction(self._and_action)

        operatorOr << (
            Group(
                operatorAnd + Suppress(Keyword("OR")) + operatorOr
            )
            | operatorAnd
        )
        operatorOr.setParseAction(self._or_action)

        parser = operatorOr + StringEnd()
        return parser
    
    def _or_action(self, string, location, tokens):
        tokens = tokens[0]
        if isinstance(tokens, Node):
            return tokens
        assert len(tokens) == 2
        return OrNode(tokens)

    def _and_action(self, string, location, tokens):
        tokens = tokens[0]
        if isinstance(tokens, Node):
            return tokens
        assert len(tokens) == 2
        return AndNode(tokens)

    def _parenthesis_action(self, string, location, tokens):
        tokens = tokens[0]
        if isinstance(tokens, Node):
            return tokens
        else:
            assert len(tokens) == 1
            return tokens[0]

    def _not_action(self, string, location, tokens):
        tokens = tokens[0]
        if isinstance(tokens, Node):
            return tokens
        assert len(tokens) == 1
        return NotNode(tokens[0])

    def _one_filter_action(self, string, location, tokens):
        if len(tokens) == 1:
            return SearchTermNode(tokens[0])
        if len(tokens) == 3:
            return SearchConditionNode(tokens[0], "", tokens[-1])
        if len(tokens) == 4:
            return SearchConditionNode(tokens[0], tokens[-2], tokens[-1])
        raise ValueError()

    @lru_cache(maxsize=100)
    def parse(self, string:str):
        if string.strip(whitespace) == "":
            return AndNode([])
        raw_result = self._parser.parse_string(string)
        assert len(raw_result) == 1
        return raw_result[0]