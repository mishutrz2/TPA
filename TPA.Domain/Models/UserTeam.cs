namespace TPA.Domain.Models
{
    public class UserTeam
    {
        public Guid UserId { get; set; }
        public ApplicationUser User { get; set; }

        public Guid TeamId { get; set; }
        public Team Team { get; set; }
    }
}
