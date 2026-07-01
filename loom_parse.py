#!/usr/bin/env python3
"""S-expression parser for LOOM sources.

The parser is frontend-agnostic. Error construction is injected explicitly to
avoid imports and circular loading.
"""

import re


class Frontend:
    __slots__ = ("error",)

    def __init__(self, error):
        self.error = error


def tokenize(frontend, src):
    # Strip `;` comments first, but never inside a quoted string.
    src = re.sub(r'"[^"]*"|;[^\n]*', lambda match: match.group(0) if match.group(0)[:1] == '"' else '', src)
    return re.findall(r'"[^"]*"|[()]|[^\s()]+', src)


def _read(frontend, tokens):
    if not tokens:
        raise frontend.error("unexpected end of input")
    head = tokens.pop(0)
    if head == ")":
        raise frontend.error("unexpected ')'")
    if head == "(":
        items = []
        while True:
            if not tokens:
                raise frontend.error("unclosed '('")
            if tokens[0] == ")":
                tokens.pop(0)
                return items
            items.append(_read(frontend, tokens))
    if head.startswith('"'):
        return head[1:-1]
    try:
        return int(head)
    except ValueError:
        return head


def parse(frontend, src):
    tokens = tokenize(frontend, src)
    out = []
    while tokens:
        out.append(_read(frontend, tokens))
    return out
