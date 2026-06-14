
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().
    AllowAnyHeader().
    AllowAnyMethod());
});

var app = builder.Build();

app.UseCors();
app.MapControllers();

app.Run();
