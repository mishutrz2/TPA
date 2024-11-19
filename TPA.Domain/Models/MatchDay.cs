namespace TPA.Domain.Models
{
    public class MatchDay
    {
        public Guid MatchDayId { get; set; }

        public DateTime MatchDayDate { get; set; }

        public int NumberOfPlayers { get; set; }

        public Guid ListId { get; set; }

        public List List {  get; set; }

        public ICollection<MatchDayTeam> MatchDayTeams { get; set; } = new List<MatchDayTeam>();

        public List<ApplicationUser> Players { get; set; } = new List<ApplicationUser>();
    }
}
