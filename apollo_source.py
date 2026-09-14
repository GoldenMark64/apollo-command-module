"""Conservative lexical C-function evidence for Apollo.

This module intentionally does not try to compile, preprocess, or semantically
interpret C.  It extracts one named function definition and reports exact source
facts that can be checked directly: source lines, simple-identifier assignments,
return statements, and recognized enclosing braced control headers.
"""
from __future__ import annotations

import re

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SIMPLE_ASSIGNMENT = re.compile(
    r"(?<![=!<>])\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<operator><<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=)(?!=)"
)
_RETURN = re.compile(r"\breturn\b")
_CONTROL = re.compile(
    r"(?s)^(?P<header>"
    r"(?:else\s+)?if\s*\(.*\)|"
    r"else|"
    r"for\s*\(.*\)|"
    r"while\s*\(.*\)|"
    r"switch\s*\(.*\)|"
    r"do"
    r")\s*$"
)


def _mask_c_noncode(text: str) -> str:
    """Replace comments/string/char contents with spaces while preserving offsets/newlines."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if text.startswith("/*", i):
            out[i] = out[i + 1] = " "
            i += 2
            while i < n:
                if text.startswith("*/", i):
                    out[i] = out[i + 1] = " "
                    i += 2
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if text[i] in ('"', "'"):
            quote = text[i]
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\\":
                    if text[i] != "\n":
                        out[i] = " "
                    i += 1
                    if i < n:
                        if text[i] != "\n":
                            out[i] = " "
                        i += 1
                    continue
                if text[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _match_delimiter(masked: str, start: int, opening: str, closing: str) -> int:
    if start >= len(masked) or masked[start] != opening:
        raise ValueError("internal delimiter start mismatch")
    depth = 0
    for i in range(start, len(masked)):
        char = masked[i]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unmatched {opening!r} while locating C function")


def _skip_space(masked: str, pos: int) -> int:
    while pos < len(masked) and masked[pos].isspace():
        pos += 1
    return pos


def _line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _find_definition(text: str, masked: str, symbol: str):
    if not _IDENTIFIER.fullmatch(symbol):
        raise ValueError("symbol must be a C identifier")
    candidates = []
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    for match in pattern.finditer(masked):
        open_paren = masked.find("(", match.start(), match.end())
        close_paren = _match_delimiter(masked, open_paren, "(", ")")
        after = _skip_space(masked, close_paren + 1)
        if after >= len(masked) or masked[after] != "{":
            continue  # prototype, call, macro use, or unsupported post-signature annotation
        close_brace = _match_delimiter(masked, after, "{", "}")
        line_start = text.rfind("\n", 0, match.start()) + 1
        candidates.append((line_start, after, close_brace))
    if not candidates:
        raise ValueError(f"function definition not found: {symbol}")
    # Multiple compile-time alternatives are deliberately not guessed between.
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    if len(unique) != 1:
        lines = [_line_number(text, item[0]) for item in unique]
        raise ValueError(f"ambiguous function definition {symbol}: candidates at lines {lines}")
    return unique[0]


def _brace_pairs(masked: str, start: int, end: int):
    stack = []
    pairs = []
    for pos in range(start, end + 1):
        char = masked[pos]
        if char == "{":
            stack.append(pos)
        elif char == "}":
            if not stack:
                raise ValueError("unbalanced closing brace in function")
            opened = stack.pop()
            pairs.append((opened, pos))
    if stack:
        raise ValueError("unbalanced opening brace in function")
    return pairs


def _control_header(masked: str, open_brace: int, function_open: int):
    if open_brace == function_open:
        return None
    boundary = max(
        masked.rfind(";", function_open + 1, open_brace),
        masked.rfind("{", function_open + 1, open_brace),
        masked.rfind("}", function_open + 1, open_brace),
    )
    chunk = _normalize_space(masked[boundary + 1:open_brace])
    match = _CONTROL.fullmatch(chunk)
    return match.group("header") if match else None


def _controls_for(pos: int, controls):
    enclosing = [(opened, header) for opened, closed, header in controls if opened < pos < closed]
    enclosing.sort(key=lambda item: item[0])
    return [header for _, header in enclosing]


def _statement_end(masked: str, pos: int, function_close: int) -> int:
    paren = bracket = 0
    for i in range(pos, function_close):
        char = masked[i]
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == ";" and paren == 0 and bracket == 0:
            return i
        elif char in "{}" and paren == 0 and bracket == 0:
            break
    raise ValueError("statement terminator not found inside function")


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _event_text(text: str, start: int, end: int) -> str:
    return text[start:end + 1].strip()


def analyze_c_function(text: str, symbol: str, variables=None, max_lines=500, max_bytes=131072):
    """Return bounded lexical evidence for one C function definition.

    ``variables`` optionally filters assignment targets.  Assignments are limited
    to simple identifier lvalues (for example ``model = expr``); member/array/
    dereference assignments are intentionally not inferred as assignments to the
    base identifier.
    """
    if not isinstance(text, str):
        raise ValueError("source text must be a string")
    if not isinstance(max_lines, int) or max_lines <= 0 or max_lines > 5000:
        raise ValueError("max_lines must be in 1..5000")
    if not isinstance(max_bytes, int) or max_bytes <= 0 or max_bytes > 1048576:
        raise ValueError("max_bytes must be in 1..1048576")
    wanted = sorted(set(variables or []))
    for variable in wanted:
        if not _IDENTIFIER.fullmatch(variable):
            raise ValueError(f"variable must be a C identifier: {variable}")

    masked = _mask_c_noncode(text)
    definition_start, function_open, function_close = _find_definition(text, masked, symbol)
    selected = text[definition_start:function_close + 1]
    start_line = _line_number(text, definition_start)
    end_line = _line_number(text, function_close)
    line_count = end_line - start_line + 1
    byte_count = len(selected.encode("utf-8"))
    if line_count > max_lines:
        raise ValueError(f"function exceeds max_lines: {line_count} > {max_lines}")
    if byte_count > max_bytes:
        raise ValueError(f"function exceeds max_bytes: {byte_count} > {max_bytes}")

    controls = []
    for opened, closed in _brace_pairs(masked, function_open, function_close):
        header = _control_header(masked, opened, function_open)
        if header:
            controls.append((opened, closed, header))

    assignments = []
    body_masked = masked[function_open + 1:function_close]
    body_base = function_open + 1
    for match in _SIMPLE_ASSIGNMENT.finditer(body_masked):
        target = match.group("target")
        if wanted and target not in wanted:
            continue
        absolute = body_base + match.start()
        end = _statement_end(masked, absolute, function_close)
        start = _line_start(text, absolute)
        assignments.append({
            "target": target,
            "operator": match.group("operator"),
            "line": _line_number(text, absolute),
            "end_line": _line_number(text, end),
            "text": _event_text(text, start, end),
            "enclosing_braced_controls": _controls_for(absolute, controls),
        })

    returns = []
    for match in _RETURN.finditer(body_masked):
        absolute = body_base + match.start()
        end = _statement_end(masked, absolute, function_close)
        expression = text[absolute + len("return"):end].strip()
        returns.append({
            "line": _line_number(text, absolute),
            "end_line": _line_number(text, end),
            "expression": expression,
            "text": _event_text(text, absolute, end),
            "enclosing_braced_controls": _controls_for(absolute, controls),
        })

    source_lines = [
        {"line": start_line + offset, "text": line}
        for offset, line in enumerate(selected.splitlines())
    ]
    limitations = [
        "lexical C analysis only; source is not preprocessed or type-resolved",
        "assignment evidence covers simple identifier lvalues only",
        "enclosing_braced_controls contains recognized braced control headers only",
        "absence of an assignment/control-flow fact is not proof that no semantic path exists",
    ]
    return {
        "symbol": symbol,
        "start_line": start_line,
        "end_line": end_line,
        "line_count": line_count,
        "bytes_utf8": byte_count,
        "sha256": __import__("hashlib").sha256(selected.encode("utf-8")).hexdigest(),
        "variables_filter": wanted,
        "source_lines": source_lines,
        "assignments": assignments,
        "returns": returns,
        "limitations": limitations,
    }
