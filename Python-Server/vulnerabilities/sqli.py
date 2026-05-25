import ast

def detect_sqli(analyzer, node):

    if not analyzer.is_execute_call(node):
        return

    for arg in node.args:
        if analyzer.is_tainted(arg):
            if analyzer.contains_sql_keyword(arg):
                vuln_type = "SQL Injection"
            else:
                vuln_type = "Possible SQL Injection"

            analyzer.vulnerabilities.append({
                "type": vuln_type,
                "line": node.lineno,
                "severity": "HIGH"
            })
