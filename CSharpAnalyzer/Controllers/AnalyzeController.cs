using CSharpAnalyzer.Dto;
using CSharpAnalyzer.Helper;
using Microsoft.AspNetCore.Mvc;

namespace CSharpAnalyzer.Controllers
{
    [ApiController]
    [Route("api/analyze")]
    public class AnalyzeController : ControllerBase
    {
        [HttpPost]
        public IActionResult Post([FromBody] AnalyzeRequest request)
        {
            var results = Analyzer.Analysis(request.Code, request.Mode);

            return Ok(results);
        }
    }
}