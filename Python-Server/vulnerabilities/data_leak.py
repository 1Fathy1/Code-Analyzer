import ast

def detect_data_leak(analyzer, node):

    if not isinstance(node, ast.Return):
        return

    if contains_sensitive_data(node.value):

        analyzer.vulnerabilities.append({
            "type": "Sensitive Data Exposure",
            "line": node.lineno,
            "severity": "HIGH"
        })


def contains_sensitive_data(node):

    keywords = ["password", "token", "secret", "api_key"]

    if isinstance(node, ast.Dict):
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if any(k in key.value.lower() for k in keywords):
                    return True

    if isinstance(node, ast.Attribute):
        if any(k in node.attr.lower() for k in keywords):
            return True

    if isinstance(node, ast.Name):
        if any(k in node.id.lower() for k in keywords):
            return True

    for child in ast.iter_child_nodes(node):
        if contains_sensitive_data(child):
            return True

    return False
