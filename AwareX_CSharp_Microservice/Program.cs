using AwareX.Security.Analyzers; // استدعاء الـ Namespace بتاع كودك

var builder = WebApplication.CreateBuilder(args);

// تفعيل الـ CORS عشان الـ Node.js يقدر يكلم السيرفر ده بأمان بدون بلوك
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

var app = builder.Build();
app.UseCors();

// الـ Endpoint اللي الـ Node.js هيضرب عليها بـ Axios
app.MapPost("/api/analyze/csharp", (AnalyzeRequest payload) =>
{
    // التأكد أن البيانات مش فاضية
    if (string.IsNullOrEmpty(payload.Code) || string.IsNullOrEmpty(payload.Mode))
    {
        return Results.BadRequest(new { status = "error", message = "المعاملات المرسلة (Code أو Mode) ناقصة!" });
    }

    // استدعاء الكلاس بتاعك وتشغيله بالظبط زي ما هو
    var analyzer = new AwareXCSharpAnalyzer();
    var result = analyzer.Analyze(payload.Code, payload.Mode);

    // إرجاع النتيجة اللي كودك حسبها للـ Node.js في شكل JSON جاهز
    return Results.Ok(result);
});

// تشغيل السيرفر على بورت 5000
app.Run("http://localhost:5000");

// الـ DTO (Data Transfer Object) لتحديد شكل الـ Request اللي جاي من الـ Node.js
public class AnalyzeRequest
{
    public string Code { get; set; }
    public string Mode { get; set; }
}