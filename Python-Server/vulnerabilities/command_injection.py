import ast

def detect_command_injection(analyzer, node):

    if not isinstance(node, ast.Call):
        return

    if isinstance(node.func, ast.Attribute):

        if node.func.attr in ["system", "popen", "run", "call"]:

            if node.args:
                if isinstance(node.args[0], ast.List):
                    return

            for arg in node.args:
                if analyzer.is_tainted(arg):
                    analyzer.vulnerabilities.append({
                        "type": "Command Injection",
                        "line": node.lineno,
                        "severity": "HIGH"
                    })
