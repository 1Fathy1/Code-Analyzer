import ast
from analyzer import SecurityAnalyzer
import json


def analyze(code, mode="all"):
    tree = ast.parse(code)

    analyzer = SecurityAnalyzer(mode=mode)
    analyzer.visit(tree)

    return analyzer.vulnerabilities

xss_safe_cases = [

    # ✅ 1. input بدون HTML
    {
        "name": "input_only",
        "code": """
x = input()
return x
""",
        "expected": False
    },

    # ✅ 2. static HTML بدون user input
    {
        "name": "static_html",
        "code": """
return "<h1>Hello</h1>"
""",
        "expected": False
    },

    # ✅ 3. escaped input (markupsafe)
    {
        "name": "escaped_input_markupsafe",
        "code": """
from markupsafe import escape
x = input()
return "<h1>" + escape(x) + "</h1>"
""",
        "expected": False
    },

    # ✅ 4. escaped input (html lib)
    {
        "name": "escaped_input_html",
        "code": """
from html import escape
x = input()
return "<div>" + escape(x) + "</div>"
""",
        "expected": False
    },

    # ✅ 5. no input + string concat
    {
        "name": "no_input_concat",
        "code": """
x = "safe"
return "<p>" + x + "</p>"
""",
        "expected": False
    },

    # ✅ 6. sanitized custom function
    {
        "name": "custom_sanitize",
        "code": """
def sanitize(x):
    return x

x = input()
return "<h1>" + sanitize(x) + "</h1>"
""",
        "expected": False
    },

    # ✅ 7. HTML بدون input
    {
        "name": "html_only",
        "code": """
return "<div><span>Hello</span></div>"
""",
        "expected": False
    },

    # ✅ 8. input مع non-html string
    {
        "name": "non_html_string",
        "code": """
x = input()
return "hello " + x
""",
        "expected": False
    },

    # ✅ 9. safe f-string بدون HTML
    {
        "name": "f_string_safe",
        "code": """
x = input()
return f"hello {x}"
""",
        "expected": False
    },

    # ✅ 10. deep chain بدون HTML
    {
        "name": "deep_chain_no_html",
        "code": """
x = input()
y = x
z = y
return z
""",
        "expected": False
    }

]

index = 1
for i in xss_safe_cases:
    print(index)
    print("----------")
    code = i["code"]
    print(code)


    print()

    print(json.dumps(analyze(code, "xss"), indent=2))
    print("------------------------------------------------")
    index += 1