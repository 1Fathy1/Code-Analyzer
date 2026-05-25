import ast

from vulnerabilities.sqli import detect_sqli
from vulnerabilities.csrf import detect_csrf
from vulnerabilities.xss import detect_xss
from vulnerabilities.command_injection import detect_command_injection
from vulnerabilities.data_leak import detect_data_leak


class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, mode="all"):
        self.mode = mode
        self.tainted_vars = set()
        self.var_values = {}
        self.vulnerabilities = []
        self.imports = {}

    def visit_Assign(self, node):

        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            self.var_values[var_name] = node.value

        if self.is_input_call(node.value):
            self.tainted_vars.add(node.targets[0].id)

        if isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_vars:
                self.tainted_vars.add(node.targets[0].id)

        self.generic_visit(node)

    def visit_Call(self, node):

        if self.mode in ["all", "sqli"]:
            detect_sqli(self, node)

        if self.mode in ["all", "cmd"]:
            detect_command_injection(self, node)

        self.generic_visit(node)

    def visit_FunctionDef(self, node):

        if self.mode in ["all", "csrf"]:
            detect_csrf(self, node)

        self.generic_visit(node)

    def visit_Return(self, node):

        if self.mode in ["all", "xss"]:
            detect_xss(self, node)

        if self.mode in ["all", "data"]:
            detect_data_leak(self, node)

        self.generic_visit(node)

    def visit_ImportFrom(self, node):

        module = node.module

        for name in node.names:
            self.imports[name.asname or name.name] = module

        self.generic_visit(node)

    # ✅ helpers

    def is_input_call(self, node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "input"
        )

    def is_execute_call(self, node):
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
        )

    def is_tainted(self, node):

        if isinstance(node, ast.Call):

            # ✅ escape / sanitize
            if isinstance(node.func, ast.Name):
                func_name = node.func.id.lower()

                module = self.imports.get(func_name, "").lower()

                if func_name in ["escape", "sanitize"] or module in ["markupsafe", "html"]:
                    return False

            for arg in node.args:
                if self.is_tainted(arg):
                    return True

        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return True

            if node.id in self.var_values:
                return self.is_tainted(self.var_values[node.id])

        if isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        return False

    def contains_sql_keyword(self, node):

        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"]

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return any(k in node.value.upper() for k in sql_keywords)

        if isinstance(node, ast.BinOp):
            return (
                self.contains_sql_keyword(node.left)
                or self.contains_sql_keyword(node.right)
            )

        if isinstance(node, ast.Name):
            if node.id in self.var_values:
                return self.contains_sql_keyword(self.var_values[node.id])

        return False