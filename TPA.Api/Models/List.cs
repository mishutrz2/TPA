namespace TPA.Api.Models
{
    public class List
    {
        public Guid ListId { get; set; }

        public string? Name { get; set; }

        public string? Location { get; set; }

        public string PasswordHash { get; set; }

        public ICollection<UserList> UserLists { get; set; } = new List<UserList>();

        public virtual ICollection<MatchDay> MatchDays { get; set; } = new List<MatchDay>();
    }
}
