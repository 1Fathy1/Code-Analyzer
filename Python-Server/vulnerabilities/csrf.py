import ast

def detect_csrf(analyzer, node):

    has_post = False
    has_csrf = False

    for decorator in node.decorator_list:

        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                if decorator.func.attr == "route":
                    for kw in decorator.keywords:
                        if kw.arg == "methods":
                            for elt in kw.value.elts:
                                if str(elt.value).upper() == "POST":
                                    has_post = True

        if isinstance(decorator, ast.Name):
            if decorator.id.lower() in ["csrf_protect", "csrf"]:
                has_csrf = True

    if has_post and not has_csrf:
        analyzer.vulnerabilities.append({
            "type": "CSRF",
            "line": node.lineno,
            "severity": "HIGH"
        })
