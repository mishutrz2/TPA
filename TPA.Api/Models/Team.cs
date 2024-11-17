namespace TPA.Api.Models
{
    public class Team
    {
        public Guid TeamId { get; set; }

        public string Name { get; set; }

        public int MatchesPlayed { get; set; }

        public int NumberOfGoalsScored { get; set; }

        public decimal Rating { get; set; }

        public ICollection<MatchDayTeam> MatchDayTeams { get; set; } // Many-to-Many with Teams

        public ICollection<UserTeam> UserTeams { get; set; } = new List<UserTeam>();
    }
}
