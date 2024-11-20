using Microsoft.AspNetCore.Mvc;
using TPA.Api.ViewModels;
using TPA.Domain.Models;
using TPA.Domain.Services.Interfaces;

namespace TPA.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ListsController : ControllerBase
    {
        private readonly IListsService _listsService;
        private readonly ILogger<ListsController> _logger;

        public ListsController(
            ILogger<ListsController> logger,
            IListsService listsService)
        {
            _logger = logger;
            this._listsService = listsService;
        }

        [HttpGet]
        public IActionResult Get()
        {
            var listOfLists = _listsService.GetLists().ToList();
            var result = listOfLists.Select(list => new ListViewModel
            {
                ListId = list.ListId,
                Name = list.Name,
                Location = list.Location,
                PasswordHash = list.PasswordHash
            })
            .ToArray();

            return Ok(result);
        }

        [HttpPost]
        public IActionResult AddList([FromBody] ListViewModel newList)
        {
            if (newList == null)
            {
                return BadRequest("Invalid data.");
            }

            try
            {
                var listToBeAdded = new List()
                {
                    ListId = Guid.NewGuid(),
                    Name = newList.Name,
                    Location = newList.Location,
                    PasswordHash = newList.PasswordHash
                };

                _listsService.AddList(listToBeAdded);

                return CreatedAtAction(nameof(GetList), new ListViewModel { ListId = listToBeAdded.ListId }, newList);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet("{listId}")]
        public IActionResult GetList(Guid listId)
        {
            var list = _listsService.GetListById(listId);

            if (list == null)
            {
                return NotFound(new { message = "List not found" });
            }

            var listViewModel = new ListViewModel()
            {
                ListId = list.ListId,
                Name = list.Name,
                Location = list.Location,
                PasswordHash = list.PasswordHash
            };

            return Ok(listViewModel);
        }
    }
}
