using Microsoft.AspNetCore.Mvc;
using TPA.Domain.Models;
using TPA.Domain.Services.Interfaces;

namespace TPA.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly IListsService _listsService;

        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(
            ILogger<WeatherForecastController> logger,
            IListsService listsService)
        {
            _logger = logger;
            this._listsService = listsService;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            var listOfLists = _listsService.GetLists().ToList();

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
