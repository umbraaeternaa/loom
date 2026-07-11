#!/usr/bin/env python3
"""S-expression parser for LOOM sources.

The parser is frontend-agnostic. Error construction is injected explicitly to
avoid imports and circular loading.
"""

class Symbol(str):
    pass


class Frontend:
    __slots__ = ("error",)

    def __init__(self, error):
        self.error = error


def tokenize_spans(frontend, src):
    """Return tokens with original 1-based line/column and byte-offset spans."""
    spans = []
    i = 0
    line = 1
    column = 1
    n = len(src)

    def advance(ch):
        nonlocal line, column
        if ch == "\n":
            line += 1
            column = 1
        else:
            column += 1

    while i < n:
        ch = src[i]
        if ch.isspace():
            advance(ch); i += 1; continue
        if ch == ";":
            while i < n and src[i] != "\n":
                advance(src[i]); i += 1
            continue
        start = i
        start_line = line
        start_column = column
        if ch in "()":
            tok = ch
            advance(ch); i += 1
        elif ch == '"':
            i += 1; advance(ch)
            while i < n:
                c = src[i]
                i += 1; advance(c)
                if c == '"':
                    break
            tok = src[start:i]
        else:
            while i < n and (not src[i].isspace()) and src[i] not in "();":
                advance(src[i]); i += 1
            tok = src[start:i]
        spans.append({"token": tok, "line": start_line, "column": start_column, "offset": start, "end_offset": i})
    return spans


def tokenize(frontend, src):
    return [span["token"] for span in tokenize_spans(frontend, src)]


def _atom_value(frontend, token):
    if token.startswith('"'):
        return token[1:-1]
    try:
        return int(token)
    except ValueError:
        return Symbol(token)


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
    return _atom_value(frontend, head)


def _span_payload(start, end):
    return {
        "line": start["line"],
        "column": start["column"],
        "offset": start["offset"],
        "end_offset": end["end_offset"],
    }


def _read_span(frontend, spans, index):
    if index >= len(spans):
        raise frontend.error("unexpected end of input")
    head = spans[index]
    token = head["token"]
    if token == ")":
        raise frontend.error("unexpected ')'")
    if token == "(":
        items = []
        children = []
        index += 1
        while True:
            if index >= len(spans):
                raise frontend.error("unclosed '('")
            if spans[index]["token"] == ")":
                close = spans[index]
                return {
                    "value": items,
                    "span": _span_payload(head, close),
                    "children": children,
                }, index + 1
            child, index = _read_span(frontend, spans, index)
            items.append(child["value"])
            children.append(child)
    return {
        "value": _atom_value(frontend, token),
        "span": _span_payload(head, head),
        "children": [],
    }, index + 1


def parse(frontend, src):
    tokens = tokenize(frontend, src)
    out = []
    while tokens:
        out.append(_read(frontend, tokens))
    return out


def parse_spans(frontend, src):
    """Return a parallel parse tree with source spans without changing parse()."""
    spans = tokenize_spans(frontend, src)
    out = []
    index = 0
    while index < len(spans):
        item, index = _read_span(frontend, spans, index)
        out.append(item)
    return out
