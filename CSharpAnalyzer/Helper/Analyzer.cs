
using System.Text;
using CSharpAnalyzer.Services;

namespace CSharpAnalyzer.Helper
{
    public static class Analyzer
    {
        public static Dictionary<string, object> Analysis(string code, string mode)
        {
            var analyzer = new AwareXCSharpAnalyzer();
            return analyzer.Analyze(code, mode);
        }

        public static string FormatOutput(Dictionary<string, object> results)
        {
            if (results["status"].ToString() == "error") return "Error: " + results["message"];

            var findings = (List<Dictionary<string, object>>)results["vulnerabilities"];
            if (findings.Count == 0) return "✅ No vulnerabilities found.";

            var sb = new StringBuilder();
            sb.AppendLine($"🔍 Found {findings.Count} vulnerability(ies):");
            foreach (var f in findings)
            {
                sb.AppendLine($"- [{f["severity"]}] {f["type"]} at line {f["line"]}");
            }
            return sb.ToString();
        }
    }
}