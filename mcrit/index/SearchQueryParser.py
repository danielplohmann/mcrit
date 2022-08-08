"""Search query parser

version 2022-08-08

This search query parser uses the excellent Pyparsing module
(http://pyparsing.sourceforge.net/) to parse search queries by users.
It handles:

* 'and', 'or' and implicit 'and' operators;
* parentheses;
* quoted strings;
* <field>:<value>
* <field>:<operator><value> for the following operators:
    <, <=, >, >=, =, !=, ? (search in a single field), !?


Requirements:
* Python
* Pyparsing


This work is based on 
https://github.com/pyparsing/pyparsing/blob/master/examples/searchparser.py
and modified by Manuel Blatt, 2022
The original license can be found below.

-------------------------------------------------------------------------------
Copyright (c) 2006, Estrate, the Netherlands
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Estrate nor the names of its contributors may be used
  to endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CONTRIBUTORS:
- Steven Mooij
- Rudolph Froger
- Paul McGuire
-------------------------------------------------------------------------------

"""

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

from mcrit.index.SearchQueryTree import AndNode, NodeType, NotNode, OrNode, SearchConditionNode, SearchTermNode

class SearchQueryParser:
    def __init__(self):
        self._methods = {
            "and": self._build_tree_and,
            "or": self._build_tree_or,
            "not": self._build_tree_not,
            "parenthesis": self._build_tree_parenthesis,
            "one_filter": self._build_tree_one_filter
        }
        self._parser = self._get_parser()
    
    def _get_parser(self):
        search_term = QuotedString('"', esc_char="\\", esc_quote='\\"') \
            | QuotedString("'", esc_char="\\", esc_quote="\\'") \
            | ZeroOrMore(Suppress(whitespace))+CharsNotIn(whitespace+"()")
        identifier = Word(identchars, identbodychars+".")
        operator = oneOf("< <= > >= = != ? !?")
        condition_compare = identifier + (":" + operator + search_term).leave_whitespace()
        condition_equal = identifier + (":" + search_term).leave_whitespace()
        one_filter = Group(condition_compare | condition_equal | search_term).setResultsName("one_filter")

        operatorOr = Forward()

        operatorParenthesis = (
            Group(Suppress("(") + operatorOr + Suppress(")")).setResultsName(
                "parenthesis"
            )
            | one_filter
        )

        operatorNot = Forward()
        operatorNot << (
            Group(Suppress(Keyword("NOT")) + operatorNot).setResultsName(
                "not"
            )
            | operatorParenthesis
        )

        operatorAnd = Forward()
        operatorAnd << (
            Group(
                operatorNot + Suppress(Keyword("AND")) + operatorAnd
            ).setResultsName("and")
            | Group(
                operatorNot + OneOrMore(~oneOf("AND OR") + operatorAnd)
            ).setResultsName("and")
            | operatorNot
        )

        operatorOr << (
            Group(
                operatorAnd + Suppress(Keyword("OR")) + operatorOr
            ).setResultsName("or")
            | operatorAnd
        )

        parser = operatorOr + StringEnd()
        return parser
    
    def _build_tree_or(self, argument) -> NodeType:
        assert len(argument) == 2
        children = [self._build_tree(child) for child in argument]
        return OrNode(children)

    def _build_tree_and(self, argument) -> NodeType:
        assert len(argument) == 2
        children = [self._build_tree(child) for child in argument]
        return AndNode(children)

    def _build_tree_parenthesis(self, argument) -> NodeType:
        assert len(argument) == 1
        return self._build_tree(argument[0])

    def _build_tree_not(self, argument) -> NodeType:
        assert len(argument) == 1
        return NotNode(self._build_tree(argument[0]))

    def _build_tree_one_filter(self, argument) -> NodeType:
        if len(argument) == 1:
            return SearchTermNode(argument[0])
        if len(argument) == 3:
            return SearchConditionNode(argument[0], "", argument[-1])
        if len(argument) == 4:
            return SearchConditionNode(argument[0], argument[-2], argument[-1])
        raise ValueError()
    
    def _build_tree(self, argument) -> NodeType:
        return self._methods[argument.getName()](argument)

    @lru_cache(maxsize=100)
    def parse(self, string:str) -> NodeType:
        if string.strip(whitespace) == "":
            return AndNode([])
        raw_result = self._parser.parse_string(string)
        assert len(raw_result) == 1
        result = self._build_tree(raw_result[0])
        return result