using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection; //  كدا مضبوطة 100%
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Linq;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// إضافة خدمات الـ Controllers ودعم الـ CORS عشان الفرونت إند يعرف يكلم الباك إند
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

var app = builder.Build();

app.UseCors();
app.MapControllers();

// تشغيل السيرفر على بورت 3000 عشان يتوافق مع ريكويست الفرونت إند
app.Run("http://localhost:3000");

namespace CSharpAnalyzer
{
    [ApiController]
    [Route("api/analyze")]
    public class AnalyzeController : ControllerBase
    {
        [HttpPost]
        public IActionResult Analyze([FromBody] AnalyzeRequest request)
        {
            if (string.IsNullOrEmpty(request.Code))
            {
                return Content("[]", "text/plain", Encoding.UTF8);
            }

            // تشغيل الفحص الذكي (لو مبعوتش نوع ثغرة هيفحص الكل "all")
            var rawFindings = Analyzer.Analysis(request.Code, request.Vuln ?? "all");
            
            // تحويل النتيجة للفورمات الصارم المطلـوب بالـ Single Quotes
            string finalResponse = Analyzer.FormatOutput(rawFindings);

            // إرسال الرد كنص صريح (Text/Plain) للمحافظة التامة على المسافات وعلامات التنصيص
            return Content(finalResponse, "text/plain", Encoding.UTF8);
        }
    }

    public class AnalyzeRequest
    {
        public string? Lan { get; set; }
        public string? Code { get; set; }
        public string? Vuln { get; set; }
    }

    public class Finding
    {
        public string? Type { get; set; }
        public int Line { get; set; }
        public string? Severity { get; set; }
    }

    public static class Analyzer
    {
        private static readonly string[] AvailableModes = { "sql", "xss", "command", "csrf" };

        public static List<Finding> Analysis(string code, string mode)
        {
            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
            var root = tree.GetCompilationUnitRoot();
            
            var targetMode = mode.ToLower();
            var allFindings = new List<Finding>();

            if (targetMode == "all")
            {
                foreach (var m in AvailableModes)
                {
                    var walker = new SecurityWalker(m);
                    walker.Visit(root);
                    allFindings.AddRange(walker.Findings);
                }
            }
            else
            {
                var walker = new SecurityWalker(targetMode);
                walker.Visit(root);
                allFindings.AddRange(walker.Findings);
            }

            // ترتيب الثغرات حسب السطور وحذف أي تكرار
            return allFindings
                .GroupBy(f => new { f.Type, f.Line })
                .Select(g => g.First())
                .OrderBy(f => f.Line)
                .ToList();
        }

        // دالة التنسيق الاحترافية لطباعة الـ Single Quotes بالمسافات المطلوبة بالملّي
        public static string FormatOutput(List<Finding> findings)
        {
            if (findings == null || findings.Count == 0) return "[]";

            var sb = new StringBuilder();
            sb.AppendLine("[");
            for (int i = 0; i < findings.Count; i++)
            {
                var item = findings[i];
                sb.AppendLine("    {");
                sb.AppendLine($"        'type': '{item.Type}',");
                sb.AppendLine($"        'line': {item.Line},");
                sb.AppendLine($"        'severity': '{item.Severity}'");
                sb.Append("    }");
                if (i < findings.Count - 1) sb.AppendLine(",");
                else sb.AppendLine();
            }
            sb.Append("]");
            return sb.ToString();
        }
    }

    class SecurityWalker : CSharpSyntaxWalker
    {
        public List<Finding> Findings { get; } = new();
        private readonly string mode;
        private readonly HashSet<string> taintedVars = new();

        public SecurityWalker(string mode) => this.mode = mode;

        private bool IsNodeTainted(SyntaxNode? node)
        {
            if (node == null) return false;
            string nodeStr = node.ToString();

            // مصادر التلوث الصريحة في دوت نت لحماية الـ False Negatives
            if (nodeStr.Contains("ReadLine") || nodeStr.Contains("Request.Query") || 
                nodeStr.Contains("Request.Form") || nodeStr.Contains("Request.Headers") || nodeStr.Contains("input"))
            {
                return true;
            }

            if (node is IdentifierNameSyntax idNode && taintedVars.Contains(idNode.Identifier.Text))
            {
                return true;
            }

            return node.ChildNodes().Any(IsNodeTainted);
        }

        public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)
        {
            if (node.Initializer != null && IsNodeTainted(node.Initializer.Value))
            {
                taintedVars.Add(node.Identifier.Text);
            }
            base.VisitVariableDeclarator(node);
        }

        public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
        {
            if (IsNodeTainted(node.Right))
            {
                taintedVars.Add(node.Left.ToString().Trim());
            }
            base.VisitAssignmentExpression(node);
        }

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            string methodName = node.Expression.ToString();

            if (mode == "sql")
            {
                bool isSqlSink = methodName.Contains("ExecuteNonQuery") || methodName.Contains("ExecuteReader") || 
                                 methodName.Contains("ExecuteScalar") || methodName.EndsWith(".Query") || methodName.EndsWith(".Execute");

                if (isSqlSink)
                {
                    bool hasTaintedArg = node.ArgumentList.Arguments.Any(arg => IsNodeTainted(arg.Expression));
                    bool isParameterized = node.ArgumentList.ToString().Contains("@") || methodName.Contains("Parameters.Add");

                    if (hasTaintedArg && !isParameterized) AddFinding("SQL Injection", node);
                }
            }

            if (mode == "xss" && (methodName.Contains("Response.Write") || methodName.Contains("Html.Raw")))
            {
                if (node.ArgumentList.Arguments.Any(arg => IsNodeTainted(arg.Expression))) AddFinding("XSS", node);
            }

            if (mode == "command" && (methodName.Contains("Process.Start") || methodName.Contains("cmd.exe")))
            {
                if (node.ArgumentList.Arguments.Any(arg => IsNodeTainted(arg.Expression))) AddFinding("Command Injection", node);
            }

            base.VisitInvocationExpression(node);
        }

        public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            if (mode == "csrf")
            {
                var attributes = node.AttributeLists.SelectMany(a => a.Attributes).Select(a => a.Name.ToString()).ToList();
                bool isPost = attributes.Any(a => a.Contains("HttpPost") || a.Contains("HttpPut") || a.Contains("HttpDelete"));
                bool hasCsrf = attributes.Any(a => a.Contains("ValidateAntiForgeryToken"));

                if (isPost && !hasCsrf) AddFinding("CSRF (Missing Protection)", node);
            }
            base.VisitMethodDeclaration(node);
        }

        private void AddFinding(string type, SyntaxNode node)
        {
            Findings.Add(new Finding
            {
                Type = type,
                Line = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                Severity = "HIGH"
            });
        }
    }
}