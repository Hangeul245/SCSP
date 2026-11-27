import ast
import json
import sys


def to_dict(node):
    if isinstance(node, ast.AST):
        d = {"_type": type(node).__name__}
        for name, value in ast.iter_fields(node):
            d[name] = to_dict(value)
        for name in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
            if hasattr(node, name):
                d[name] = getattr(node, name)
        return d
    if isinstance(node, list):
        return [to_dict(x) for x in node]
    if node is None or isinstance(node, (str, int, float)):
        return node
    return repr(node)


def main():
    source = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as e:
        json.dump({"_error": type(e).__name__, "lineno": getattr(e, "lineno", None)}, sys.stdout)
        return
    json.dump(to_dict(tree), sys.stdout)


if __name__ == "__main__":
    main()