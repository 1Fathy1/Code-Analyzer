import ast

def detect_xss(analyzer, node):

    if not isinstance(node, ast.Return):
        return

    value = node.value

    if not analyzer.is_tainted(value):
        return

    if is_sanitized(analyzer, value):
        return

    if contains_html(value):
        vuln_type = "XSS"
        severity = "HIGH"
    else:
        vuln_type = "Possible XSS"
        severity = "MEDIUM"

    analyzer.vulnerabilities.append({
        "type": vuln_type,
        "line": node.lineno,
        "severity": severity
    })


def contains_html(node):

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "<" in node.value and ">" in node.value

    if isinstance(node, ast.BinOp):
        return (
            contains_html(node.left) or
            contains_html(node.right)
        )

    return False


def is_sanitized(analyzer, node):

    if isinstance(node, ast.Call):

        if isinstance(node.func, ast.Name):
            func_name = node.func.id.lower()
            module = analyzer.imports.get(func_name, "").lower()

            if func_name in ["escape", "sanitize"] or module in ["markupsafe", "html"]:
                return True

        for arg in node.args:
            if is_sanitized(analyzer, arg):
                return True

    if isinstance(node, ast.BinOp):
        return (
            is_sanitized(analyzer, node.left)
            or is_sanitized(analyzer, node.right)
        )

    return False