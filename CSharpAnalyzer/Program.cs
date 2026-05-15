using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace CSharpAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            // كود الاختبار الشامل - تأكدي من وجود [HttpPost] للـ CSRF
            string codeToScan =
             @"public class UserAccountController : Controller {
    
    // ثغرة: POST بدون حماية
    [HttpPost]
    public void UpdateProfile(string data) {
        // logic
    }

    // آمنة: POST مع حماية
    [HttpPost]
    [ValidateAntiForgeryToken]
    public void SecureUpdate(string data) {
        // logic
    }";

            SyntaxTree tree = CSharpSyntaxTree.ParseText(codeToScan);
            var root = tree.GetCompilationUnitRoot();
            
            var analyzer = new SecurityWalker();
            analyzer.Visit(root);

            Console.WriteLine("[");
            for (int i = 0; i < analyzer.Findings.Count; i++)
            {
                var f = analyzer.Findings[i];
                Console.WriteLine($"  {{ \"type\": \"{f.Type}\", \"line\": {f.Line}, \"severity\": \"{f.Severity}\" }}{ (i < analyzer.Findings.Count - 1 ? "," : "") }");
            }
            Console.WriteLine("]");
        }
    }

    class SecurityWalker : CSharpSyntaxWalker
    {
        public List<Finding> Findings = new List<Finding>();
        private HashSet<string> taintedVars = new HashSet<string>();

        // 1. تتبع التلوث عند تعريف المتغيرات لأول مرة (string x = input)
        public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)
        {
            if (node.Initializer != null)
            {
                string rightSide = node.Initializer.Value.ToString();
                if (rightSide.Contains("ReadLine") || rightSide.Contains("input") || taintedVars.Any(t => rightSide.Contains(t)))
                {
                    taintedVars.Add(node.Identifier.Text);
                }
            }
            base.VisitVariableDeclarator(node);
        }

        // 2. تتبع التلوث عند إعادة التعيين (x = input)
        public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
        {
            string rightSide = node.Right.ToString();
            if (rightSide.Contains("ReadLine") || rightSide.Contains("input") || taintedVars.Any(t => rightSide.Contains(t)))
            {
                taintedVars.Add(node.Left.ToString());
            }
            base.VisitAssignmentExpression(node);
        }

        // 3. فحص الـ Sinks (SQL, XSS, Command, Exposure)
        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            string methodName = node.Expression.ToString();
            string args = node.ArgumentList.ToString();

            // SQL Injection
            if ((methodName.Contains("Execute") || methodName.Contains("Query")) && taintedVars.Any(t => args.Contains(t)) && !args.Contains("@"))
                AddFinding("SQL Injection", node);

            // Command Injection
            if (methodName.Contains("Process.Start") && taintedVars.Any(t => args.Contains(t)))
                AddFinding("Command Injection", node);

            // XSS
            if (methodName.Contains("Response.Write") && taintedVars.Any(t => args.Contains(t)))
                AddFinding("XSS", node);

            // Data Exposure
            if ((methodName.Contains("WriteLine") || methodName.Contains("Log")) && (args.ToLower().Contains("pass") || args.ToLower().Contains("secret")))
                AddFinding("Data Exposure", node);

            base.VisitInvocationExpression(node);
        }

        // 4. فحص الـ CSRF (الثغرة الخامسة)
        public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            var attributes = node.AttributeLists.SelectMany(a => a.Attributes).Select(a => a.Name.ToString());
            bool isPost = attributes.Any(a => a.Contains("HttpPost"));
            bool hasCsrf = attributes.Any(a => a.Contains("ValidateAntiForgeryToken"));

            if (isPost && !hasCsrf)
            {
                AddFinding("CSRF (Missing Protection)", node);
            }
            base.VisitMethodDeclaration(node);
        }

        private void AddFinding(string type, SyntaxNode node)
        {
            Findings.Add(new Finding {
                Type = type,
                Line = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                Severity = "HIGH"
            });
        }
    }

    class Finding { public string? Type { get; set; } public int Line { get; set; } public string? Severity { get; set; } }
}