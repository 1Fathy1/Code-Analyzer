using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace CSharpAnalyzer.Services
{
    public class AwareXCSharpAnalyzer
    {
        private class SecurityWalker : CSharpSyntaxWalker
        {
            public List<Dictionary<string, object>> Findings = new List<Dictionary<string, object>>();
            private string _mode;
            private HashSet<string> _taintedVars = new HashSet<string>();

            public SecurityWalker(string mode) { _mode = mode.ToLower().Trim(); }

            private bool IsExpressionTainted(ExpressionSyntax expression)
            {
                if (expression == null) return false;

                // Check if it's a known tainted variable
                if (expression is IdentifierNameSyntax identifier && _taintedVars.Contains(identifier.Identifier.Text)) return true;

                // Taint Sources: Console.ReadLine, Request.Query, Request.Form, input
                string exprString = expression.ToString();
                if (exprString.Contains("Console.ReadLine") ||
                    exprString.Contains("Request.Query") ||
                    exprString.Contains("Request.Form") ||
                    exprString == "input") return true;

                // Propagation via Binary Expressions (concatenation)
                if (expression is BinaryExpressionSyntax binary && (IsExpressionTainted(binary.Left) || IsExpressionTainted(binary.Right))) return true;

                // Propagation via Interpolation
                if (expression is InterpolatedStringExpressionSyntax) return true;

                return false;
            }

            public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)
            {
                if (node.Initializer != null && IsExpressionTainted(node.Initializer.Value))
                {
                    _taintedVars.Add(node.Identifier.Text);
                }
                base.VisitVariableDeclarator(node);
            }

            public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
            {
                if (IsExpressionTainted(node.Right) && node.Left is IdentifierNameSyntax identifier)
                {
                    _taintedVars.Add(identifier.Identifier.Text);
                }
                base.VisitAssignmentExpression(node);
            }

            public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
            {
                base.VisitMethodDeclaration(node);
                CheckMethodForCsrf(node, node.AttributeLists);
            }

            public override void VisitLocalFunctionStatement(LocalFunctionStatementSyntax node)
            {
                base.VisitLocalFunctionStatement(node);
                CheckMethodForCsrf(node, node.AttributeLists);
            }

            private void CheckMethodForCsrf(SyntaxNode node, SyntaxList<AttributeListSyntax> attributeLists)
            {
                if (_mode != "csrf" && _mode != "all") return;

                var allAttributes = attributeLists.SelectMany(al => al.Attributes).ToList();
                bool hasHttpPost = allAttributes.Any(a => a.Name.ToString().Contains("HttpPost"));
                bool hasCsrfProtection = allAttributes.Any(a => a.Name.ToString().Contains("ValidateAntiForgeryToken"));

                if (hasHttpPost && !hasCsrfProtection)
                {
                    AddFinding("Missing CSRF [ValidateAntiForgeryToken] Attribute", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "HIGH");
                }
            }

            public override void VisitInvocationExpression(InvocationExpressionSyntax node)
            {
                string methodName = node.Expression.ToString();

                // Check all arguments for taint
                bool isAnyArgumentTainted = node.ArgumentList.Arguments.Any(arg => IsExpressionTainted(arg.Expression));

                // 1. SQL Injection
                if (_mode == "sql" || _mode == "all")
                {
                    if (methodName.Contains("ExecuteNonQuery") || methodName.Contains("ExecuteReader") ||
                        methodName.Contains("FromSqlRaw") || methodName.Contains("Query"))
                    {
                        if (isAnyArgumentTainted)
                        {
                            AddFinding("SQL Injection", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "CRITICAL");
                        }
                    }
                }

                // 2. Command Injection
                if (_mode == "command" || _mode == "all")
                {
                    if (methodName.Contains("Process.Start"))
                    {
                        if (isAnyArgumentTainted)
                        {
                            AddFinding("Command Injection", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "CRITICAL");
                        }
                    }
                }

                // 3. XSS
                if (_mode == "xss" || _mode == "all")
                {
                    if (methodName.Contains("Html.Raw") || methodName.Contains("Response.Write"))
                    {
                        if (isAnyArgumentTainted)
                        {
                            AddFinding("Cross-Site Scripting (XSS)", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "HIGH");
                        }
                    }
                }

                // 4. Exposure
                if (_mode == "exposure" || _mode == "all")
                {
                    if (methodName.Contains("MD5.Create") || methodName.Contains("SHA1.Create"))
                    {
                        AddFinding("Sensitive Data Exposure (Weak Cryptography)", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "MEDIUM");
                    }
                }

                base.VisitInvocationExpression(node);
            }

            private void AddFinding(string type, int line, string severity)
            {
                Findings.Add(new Dictionary<string, object> { { "type", type }, { "line", line }, { "severity", severity } });
            }
        }

        public Dictionary<string, object> Analyze(string userCode, string userMode)
        {
            try
            {
                SyntaxTree tree = CSharpSyntaxTree.ParseText(userCode);
                var root = tree.GetCompilationUnitRoot();

                var walker = new SecurityWalker(userMode);
                walker.Visit(root);

                return new Dictionary<string, object> {
                { "status", "success" },
                { "vulnerabilities", walker.Findings }
            };
            }
            catch (Exception ex)
            {
                return new Dictionary<string, object> { { "status", "error" }, { "message", ex.Message } };
            }
        }
    }
}