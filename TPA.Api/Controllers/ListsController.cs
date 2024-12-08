using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.JsonPatch;
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

        [Authorize]
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

        [HttpPut("{listId}")]
        public IActionResult UpdateList(Guid listId, [FromBody] ListViewModel updatedList)
        {
            if (updatedList == null)
            {
                return BadRequest("Invalid data.");
            }

            try
            {
                var listEntity = new List
                {
                    Name = updatedList.Name,
                    Location = updatedList.Location,
                    PasswordHash = updatedList.PasswordHash
                };

                _listsService.UpdateList(listId, listEntity);

                return NoContent(); // 204 No Content
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message }); // Return 404 if the list is not found
            }
        }

        [HttpPatch("{listId}")]
        public IActionResult UpdateListPartial(Guid listId, [FromBody] JsonPatchDocument<ListViewModel> patchDoc)
        {
            if (patchDoc == null)
            {
                return BadRequest("Invalid data.");
            }

            try
            {
                // Retrieve the existing list
                var existingList = _listsService.GetListById(listId);
                if (existingList == null)
                {
                    return NotFound(new { message = "List not found" });
                }

                // Apply the patch to the view model
                var listViewModel = new ListViewModel
                {
                    Name = existingList.Name,
                    Location = existingList.Location,
                    PasswordHash = existingList.PasswordHash
                };
                patchDoc.ApplyTo(listViewModel, ModelState);

                // Validate the patch
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Map the patched ViewModel back to the entity
                var listEntity = new List
                {
                    Name = listViewModel.Name,
                    Location = listViewModel.Location,
                    PasswordHash = listViewModel.PasswordHash
                };

                _listsService.UpdateList(listId, listEntity);

                return NoContent(); // 204 No Content
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}
