using AwareX.Security.Analyzers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

var app = builder.Build();
app.UseCors();

app.MapPost("/api/analyze/csharp", (AnalyzeRequest payload) =>
{
    if (string.IsNullOrEmpty(payload.code) || string.IsNullOrEmpty(payload.vuln))
    {
        return Results.BadRequest(new { status = "error", message = "المعاملات المرسلة (code أو vuln) ناقصة!" });
    }

    var analyzer = new AwareXCSharpAnalyzer();
    var result = analyzer.Analyze(payload.code, payload.vuln);

    return Results.Ok(result);
});

app.Run("http://localhost:5000");

public class AnalyzeRequest
{
    public string? code { get; set; }
    public string? vuln { get; set; }
    public string? lan { get; set; }
}