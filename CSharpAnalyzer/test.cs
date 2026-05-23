using System;
using System.Runtime.CompilerServices;

namespace CSharpAnalyzer
{
    public static class TestRunner
    {
        // الميثود دي بتشتغل لوحدها أول ما السيرفر يقوم عشان تطبع التيست كيسز في الـ Terminal فوراً
        [ModuleInitializer]
        public static void RunLocalTests()
        {
            var testCases = new[]
            {
                new { Id = 1, Desc = "Direct SQL Injection", Code = "var x = Console.ReadLine();\ncmd.ExecuteNonQuery(\"SELECT * FROM Users WHERE Id = \" + x);", Mode = "sql" },
                new { Id = 2, Desc = "Safe Constant Query (No Issues)", Code = "var x = Console.ReadLine();\ncmd.ExecuteNonQuery(\"SELECT * FROM Users WHERE Id = 5\");", Mode = "sql" },
                new { Id = 3, Desc = "Intermediate Variable Injection", Code = "var x = Request.Query[\"id\"];\nstring query = \"SELECT * FROM Users WHERE Id = \" + x;\ncmd.ExecuteReader(query);", Mode = "sql" },
                new { Id = 4, Desc = "Taint Propagation via Assignment", Code = "var x = input;\nvar y = x;\ncmd.ExecuteNonQuery(\"SELECT * FROM Users WHERE Id = \" + y);", Mode = "sql" },
                new { Id = 5, Desc = "Safe Parameterized Query (No Issues)", Code = "var x = Request.Form[\"id\"];\ncmd.CommandText = \"SELECT * FROM Users WHERE Id = @id\";\ncmd.Parameters.AddWithValue(\"@id\", x);", Mode = "sql" },
                new { Id = 6, Desc = "XSS Vulnerability", Code = "var data = Request.Query[\"name\"];\nResponse.Write(data);", Mode = "xss" },
                new { Id = 7, Desc = "Command Injection Vulnerability", Code = "var path = input;\nSystem.Diagnostics.Process.Start(\"cmd.exe\", \"/c delete \" + path);", Mode = "command" },
                new { Id = 8, Desc = "CSRF Missing Protection on Post", Code = "[HttpPost]\npublic IActionResult Update() {\n    return Ok();\n}", Mode = "csrf" },
                new { Id = 9, Desc = "Select All Mode (SQL + XSS + CSRF)", Code = "var input = Console.ReadLine();\ncmd.ExecuteNonQuery(\"SELECT * FROM Products WHERE Name = \" + input);\nResponse.Write(input);\n[HttpPost]\npublic void Save() {}", Mode = "all" }
            };

            Console.WriteLine("=== 🛡️ Start C# Roslyn AST & Taint Analysis Local Testing ===\n");

            foreach (var t in testCases)
            {
                var rawResults = Analyzer.Analysis(t.Code, t.Mode);
                string formattedString = Analyzer.FormatOutput(rawResults);

                Console.WriteLine("--------------------------------------------------");
                Console.WriteLine($"ID: {t.Id} | Mode: [{t.Mode}] | Desc: {t.Desc}");
                Console.WriteLine(formattedString);
            }
            Console.WriteLine("--------------------------------------------------\n");
            Console.WriteLine("=== 🚀 Web API Server Running & Ready for Front-End Requests ===");
        }
    }
}