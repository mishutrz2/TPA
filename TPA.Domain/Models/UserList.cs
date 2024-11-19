using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace TPA.Domain.Models
{
    public class UserList
    {
        [Key]
        [Column(Order = 0)]
        public Guid ApplicationUserId { get; set; }

        public ApplicationUser User { get; set; }

        [Key]
        [Column(Order = 1)]
        public Guid ListId { get; set; }

        public List List { get; set; }
    }
}
