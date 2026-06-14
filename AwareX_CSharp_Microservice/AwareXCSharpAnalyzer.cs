using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace AwareX.Security.Analyzers
{
    public class AwareXCSharpAnalyzer
    {
        private class SecurityWalker : CSharpSyntaxWalker
        {
            public List<Dictionary<string, string>> Findings { get; } = new List<Dictionary<string, string>>();
            private readonly string _mode;
            private readonly HashSet<string> _taintedVars = new HashSet<string>();

            public SecurityWalker(string mode)
            {
                _mode = (mode ?? string.Empty).ToLower().Trim();
            }

            private void AddFinding(string type, int line, string severity)
            {
                Findings.Add(new Dictionary<string, string>
                {
                    {"line", line.ToString()},
                    {"severity", severity},
                    {"type", type}
                });
            }
private bool IsUserInput(string text)
{
    // توسيع نطاق البحث ليشمل أي كود يحتوي على Request. أو Console.ReadLine
    string[] sources = new[]
    {
        "Console.ReadLine",
        "Request.", 
        "Query",
        "Form",
        "Params",
        "HttpContext.Current.Request"
    };

    return sources.Any(text.Contains);
}

            private bool IsExpressionTainted(ExpressionSyntax expression)
            {
                if (expression == null) return false;

                if (expression is IdentifierNameSyntax id)
                {
                    return _taintedVars.Contains(id.Identifier.Text);
                }

                if (IsUserInput(expression.ToString())) return true;

                if (expression is InvocationExpressionSyntax inv && IsUserInput(inv.ToString())) return true;

                if (expression is BinaryExpressionSyntax binary)
                {
                    return IsExpressionTainted(binary.Left) || IsExpressionTainted(binary.Right);
                }

                if (expression is InterpolatedStringExpressionSyntax interp)
                {
                    foreach (var item in interp.Contents)
                    {
                        if (item is InterpolationSyntax i && IsExpressionTainted(i.Expression))
                            return true;
                    }
                    return false;
                }

                if (expression is ParenthesizedExpressionSyntax p)
                {
                    return IsExpressionTainted(p.Expression);
                }

                if (expression is ConditionalExpressionSyntax cond)
                {
                    return IsExpressionTainted(cond.WhenTrue) || IsExpressionTainted(cond.WhenFalse);
                }

                if (expression is MemberAccessExpressionSyntax member && IsUserInput(member.ToString())) return true;
                if (expression is ElementAccessExpressionSyntax element && IsUserInput(element.ToString())) return true;

                return false;
            }

            private bool IsSqlSink(string method)
            {
                return method.Contains("SqlCommand") ||
                       method.Contains("ExecuteReader") ||
                       method.Contains("ExecuteScalar") ||
                       method.Contains("ExecuteNonQuery") ||
                       method.Contains("ExecuteXmlReader") ||
                       method.Contains("FromSqlRaw") ||
                       method.Contains("ExecuteSqlRaw") ||
                       method.Contains("Query");
            }

            private bool IsXssSink(string method)
            {
                return method.Contains("Response.Write") ||
                       method.Contains("Html.Raw") ||
                       method.Contains("WriteLiteral") ||
                       method.Contains("InnerHtml");
            }

            private bool IsCommandSink(string method)
            {
                return method.Contains("Process.Start") ||
                       method.Contains("ProcessStartInfo");
            }

            private bool IsWeakCrypto(string method)
            {
                return method.Contains("MD5.Create") ||
                       method.Contains("SHA1.Create") ||
                       method.Contains("DES.Create") ||
                       method.Contains("TripleDES.Create") ||
                       method.Contains("RC2.Create") ||
                       method.Contains("PasswordDeriveBytes");
            }

            public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)
            {
                try
                {
                    if (node.Initializer != null && IsExpressionTainted(node.Initializer.Value))
                    {
                        _taintedVars.Add(node.Identifier.Text);
                    }
                }
                catch { }
                base.VisitVariableDeclarator(node);
            }

            public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
            {
                try
                {
                    if (IsExpressionTainted(node.Right) && node.Left is IdentifierNameSyntax id)
                    {
                        _taintedVars.Add(id.Identifier.Text);
                    }
                }
                catch { }
                base.VisitAssignmentExpression(node);
            }

            public override void VisitParameter(ParameterSyntax node)
            {
                try
                {
                    if ((_mode == "xss" || _mode == "sql" || _mode == "command") && 
                        node.Type != null && node.Type.ToString() == "string")
                    {
                        _taintedVars.Add(node.Identifier.Text);
                    }
                }
                catch { }
                base.VisitParameter(node);
            }

            public override void VisitLocalDeclarationStatement(LocalDeclarationStatementSyntax node)
            {
                try
                {
                    foreach (var v in node.Declaration.Variables)
                    {
                        if (v.Initializer != null && IsExpressionTainted(v.Initializer.Value))
                        {
                            _taintedVars.Add(v.Identifier.Text);
                        }
                    }
                }
                catch { }
                base.VisitLocalDeclarationStatement(node);
            }

            public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
            {
                try
                {
                    bool hasHttpPost = false;
                    bool hasCsrf = false;

                    var attrs = node.AttributeLists.SelectMany(x => x.Attributes);

                    foreach (var a in attrs)
                    {
                        string name = a.Name.ToString();
                        if (name.Contains("HttpPost")) hasHttpPost = true;
                        if (name.Contains("ValidateAntiForgeryToken")) hasCsrf = true;
                    }

                    if (_mode == "csrf" && hasHttpPost && !hasCsrf)
                    {
                        var lineSpan = node.GetLocation().GetLineSpan();
                        AddFinding("Missing CSRF Validation", lineSpan.StartLinePosition.Line + 1, "HIGH");
                    }
                }
                catch { }
                base.VisitMethodDeclaration(node);
            }

            public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
            {
                try
                {
                    string obj = node.Type.ToString();

                    if (_mode == "sql" && obj.Contains("SqlCommand") && node.ArgumentList?.Arguments.Count > 0)
                    {
                        if (IsExpressionTainted(node.ArgumentList.Arguments[0].Expression))
                        {
                            var lineSpan = node.GetLocation().GetLineSpan();
                            AddFinding("SQL Injection", lineSpan.StartLinePosition.Line + 1, "CRITICAL");
                        }
                    }

                    if (_mode == "command" && obj.Contains("ProcessStartInfo") && node.ArgumentList != null)
                    {
                        foreach (var arg in node.ArgumentList.Arguments)
                        {
                            if (IsExpressionTainted(arg.Expression))
                            {
                                var lineSpan = node.GetLocation().GetLineSpan();
                                AddFinding("Command Injection", lineSpan.StartLinePosition.Line + 1, "CRITICAL");
                                break;
                            }
                        }
                    }
                }
                catch { }
                base.VisitObjectCreationExpression(node);
            }

            public override void VisitInvocationExpression(InvocationExpressionSyntax node)
            {
                try
                {
                    string methodName = node.Expression.ToString();
                    var lineSpan = node.GetLocation().GetLineSpan();
                    int line = lineSpan.StartLinePosition.Line + 1;

                    if (_mode == "sql" && IsSqlSink(methodName))
                    {
                        foreach (var arg in node.ArgumentList.Arguments)
                        {
                            if (IsExpressionTainted(arg.Expression))
                            {
                                AddFinding("SQL Injection", line, "CRITICAL");
                                break;
                            }
                        }
                    }

                    if (_mode == "xss" && IsXssSink(methodName))
                    {
                        foreach (var arg in node.ArgumentList.Arguments)
                        {
                            if (IsExpressionTainted(arg.Expression))
                            {
                                AddFinding("Cross-Site Scripting (XSS)", line, "HIGH");
                                break;
                            }
                        }
                    }

                    if (_mode == "command" && IsCommandSink(methodName))
                    {
                        foreach (var arg in node.ArgumentList.Arguments)
                        {
                            if (IsExpressionTainted(arg.Expression))
                            {
                                AddFinding("Command Injection", line, "CRITICAL");
                                break;
                            }
                        }
                    }

                    if (_mode == "exposure" && IsWeakCrypto(methodName))
                    {
                        AddFinding("Sensitive Data Exposure (Weak Cryptography)", line, "MEDIUM");
                    }
                }
                catch { }
                base.VisitInvocationExpression(node);
            }
        }
public Dictionary<string, object> Analyze(string userCode, string userMode)
{
    try
    {
        string processedCode = (userCode ?? string.Empty).Trim();

        // فحص ذكي لهيكل الكود
        if (!processedCode.Contains("class "))
        {
            // إذا كان الكود يحتوي على اتريبيوت أو دوال تحكم، نلفه في كلاس فقط
            if (processedCode.Contains("HttpPost") || processedCode.Contains("IActionResult") || processedCode.Contains("public"))
            {
                processedCode = "public class DynamicController \n{\n" + processedCode + "\n}";
            }
            // إذا كان مجرد أسطر برمجية عادية (Statements)، نلفه في كلاس ودالة افتراضية
            else
            {
                processedCode = "public class DynamicClass \n{\n" +
                                "    public void DynamicMethod() \n" +
                                "    {\n        " + processedCode + "\n    }\n" +
                                "}";
            }
        }

        SyntaxTree tree = CSharpSyntaxTree.ParseText(processedCode);
        CompilationUnitSyntax root = tree.GetCompilationUnitRoot();
        SecurityWalker walker = new SecurityWalker(userMode);
        walker.Visit(root);

        return new Dictionary<string, object>
        {
            {"status", "success"},
            {"vulnerabilities", walker.Findings}
        };
    }
    catch (Exception ex)
    {
        return new Dictionary<string, object>
        {
            {"status", "error"},
            {"message", ex.Message}
        };
    }
}
    }
}