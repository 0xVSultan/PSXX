"""A small reader of C sources for the text tools (tools/ui_lint.py, tools/ui_convert.py): the tokens with their place in the file, and the string literals the way the compiler joins them
(adjacent literals and the button icons ICO_CROSS ... between them make one text). It does not run the preprocessor."""
import re

ICO = re.compile(r"ICO_[A-Z0-9_]+")
ICO_BYTE = {"CROSS": 1, "CIRCLE": 2, "SQUARE": 3, "TRIANGLE": 4, "START": 5, "SELECT": 6, "UP": 7, "DOWN": 8, "LEFT": 9, "RIGHT": 10, "UPDOWN": 11, "LEFTRIGHT": 12,
            "L1": 13, "L2": 14, "R1": 15, "R2": 16, "DPAD": 17, "EYES": 18}


def tokens(src):
    """(kind, value, line, start, end): kind 'id', 'str' (value = the text between the quotes, as written), 'chr', 'num', 'p' (a punctuation character)"""
    out, i, n, line = [], 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1; i += 1
        elif c.isspace():
            i += 1
        elif src.startswith("//", i):
            while i < n and src[i] != "\n": i += 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j); i = j
        elif c == "#" and re.match(r"[ \t]*#", src[src.rfind("\n", 0, i) + 1:i + 1]):
            j = i
            while j < n and src[j] != "\n":
                if src[j] == "\\" and j + 1 < n and src[j + 1] == "\n":
                    line += 1; j += 2; continue
                j += 1
            if re.match(r"#\s*(include|if|ifdef|ifndef|elif|else|endif|pragma|undef|error)\b", src[i:j]):
                i = j
            else:
                i += 1                                       # #define: its body is code
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(("str", src[i + 1:j], line, i, j + 1)); i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            out.append(("chr", src[i:j + 1], line, i, j + 1)); i = j + 1
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"): j += 1
            out.append(("id", src[i:j], line, i, j)); i = j
        elif c.isdigit():
            j = i
            while j < n and (src[j].isalnum() or src[j] in "._"): j += 1
            out.append(("num", src[i:j], line, i, j)); i = j
        else:
            out.append(("p", c, line, i, i + 1)); i += 1
    return out


def unesc(s):
    """the bytes of a C string literal body: a character of the source is its UTF-8, an escape \\xHH is that byte"""
    out, i = bytearray(), 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                j = i + 2
                while j < len(s) and j < i + 4 and s[j] in "0123456789abcdefABCDEF": j += 1
                out.append(int(s[i + 2:j], 16)); i = j; continue
            out += {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}.get(n, n).encode("utf-8"); i += 2; continue
        out += s[i].encode("utf-8"); i += 1
    return bytes(out)


def sequences(src):
    """[(line, text, callee, start, end)]: the joined literals; text is bytes (icons as bytes 1..18); callee the nearest enclosing function-call name"""
    toks = tokens(src)
    out, stack, i = [], [], 0
    while i < len(toks):
        k, v = toks[i][0], toks[i][1]
        if k == "p" and v == "(":
            stack.append(toks[i - 1][1] if i and toks[i - 1][0] == "id" else "")
        elif k == "p" and v == ")":
            if stack: stack.pop()
        elif k == "str" or (k == "id" and ICO.fullmatch(v)):
            j, text, seen_str = i, b"", False
            while j < len(toks) and (toks[j][0] == "str" or (toks[j][0] == "id" and ICO.fullmatch(toks[j][1]))):
                if toks[j][0] == "str":
                    text += unesc(toks[j][1]); seen_str = True
                else:
                    text += bytes([ICO_BYTE.get(toks[j][1][4:], 1)])
                j += 1
            if seen_str:
                callee = next((c for c in reversed(stack) if c), "")
                out.append((toks[i][2], text, callee, toks[i][3], toks[j - 1][4]))
            i = j
            continue
        i += 1
    return out
