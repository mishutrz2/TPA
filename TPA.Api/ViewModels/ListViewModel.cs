using TPA.Domain.Models;

namespace TPA.Api.ViewModels
{
    public class ListViewModel
    {
        public Guid ListId { get; set; }

        public string? Name { get; set; }

        public string? Location { get; set; }

        public string PasswordHash { get; set; }
    }
}
