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
            public List<Dictionary<string, string>> Findings = new List<Dictionary<string, string>>();
            private string _mode;
            private HashSet<string> _taintedVars = new HashSet<string>();
            private bool _hasCsrfAttribute = false;

            public SecurityWalker(string mode) { _mode = mode.ToLower().Trim(); }

            private bool IsExpressionTainted(ExpressionSyntax expression)
            {
                if (expression is IdentifierNameSyntax identifier && _taintedVars.Contains(identifier.Identifier.Text)) return true;
                if (expression is InvocationExpressionSyntax invocation && invocation.ToString().Contains("Console.ReadLine")) return true;
                if (expression is BinaryExpressionSyntax binary && (IsExpressionTainted(binary.Left) || IsExpressionTainted(binary.Right))) return true;
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

            public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
            {
                var attributes = node.AttributeLists.SelectMany(al => al.Attributes).Select(a => a.Name.ToString()).ToList();
                if (attributes.Contains("HttpPost") && attributes.Contains("ValidateAntiForgeryToken"))
                {
                    _hasCsrfAttribute = true;
                }
                base.VisitMethodDeclaration(node);
            }

            public override void VisitInvocationExpression(InvocationExpressionSyntax node)
            {
                string methodName = node.Expression.ToString();

                // 1. فحص SQL Injection
                if (_mode == "sql" && (methodName.Contains("ExecuteNonQuery") || methodName.Contains("FromSqlRaw") || methodName.Contains("Query")))
                {
                    if (node.ArgumentList.Arguments.Count > 0 && IsExpressionTainted(node.ArgumentList.Arguments[0].Expression))
                    {
                        AddFinding("SQL Injection", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "CRITICAL");
                    }
                }

                // 2. فحص Command Injection
                if (_mode == "command" && methodName.Contains("Process.Start"))
                {
                    if (node.ArgumentList.Arguments.Count > 0 && IsExpressionTainted(node.ArgumentList.Arguments[0].Expression))
                    {
                        AddFinding("Command Injection", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "CRITICAL");
                    }
                }

                // 3. فحص XSS
                if (_mode == "xss" && (methodName.Contains("Html.Raw") || methodName.Contains("Response.Write")))
                {
                    if (node.ArgumentList.Arguments.Count > 0 && IsExpressionTainted(node.ArgumentList.Arguments[0].Expression))
                    {
                        AddFinding("Cross-Site Scripting (XSS)", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "HIGH");
                    }
                }

                // 4. فحص Sensitive Data Exposure
                if (_mode == "exposure" && (methodName.Contains("MD5.Create") || methodName.Contains("SHA1.Create")))
                {
                    AddFinding("Sensitive Data Exposure (Weak Cryptography)", node.GetLocation().GetLineSpan().StartLinePosition.Line + 1, "MEDIUM");
                }

                base.VisitInvocationExpression(node);
            }

            public void CheckFinalCsrf()
            {
                if (_mode == "csrf" && !_hasCsrfAttribute) AddFinding("Missing CSRF [ValidateAntiForgeryToken] Attribute", 1, "HIGH");
            }

            private void AddFinding(string type, int line, string severity)
            {
                // التعديل الأول 🛠️: تغيير الـ Key ليكون "type" بدلاً من "vulnerability"
                Findings.Add(new Dictionary<string, string> { { "line", line.ToString() }, { "severity", severity }, { "type", type } });
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
                walker.CheckFinalCsrf(); 

                // التعديل الثاني 🛠️: إرجاع الـ "vulnerabilities" مباشرة بشكلها الجديد
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