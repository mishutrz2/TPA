using Microsoft.AspNetCore.Mvc;
using TPA.Api.Models;

namespace TPA.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;

        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(
            ILogger<WeatherForecastController> logger,
            ApplicationDbContext dbContext)
        {
            _logger = logger;
            this._dbContext = dbContext;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            var listOfLists = _dbContext.Lists.ToList();

            return listOfLists.Select(list => new WeatherForecast
            {
                Date = DateOnly.MaxValue,
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = list.Name
            })
            .ToArray();
        }
    }
}
