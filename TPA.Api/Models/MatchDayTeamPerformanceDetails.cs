namespace TPA.Api.Models
{
    public class MatchDayTeamPerformanceDetails
    {
        public Guid MatchDayId { get; set; }

        public Guid TeamId { get; set; }

        public MatchDayTeam MatchDayTeam { get; set; }

        public decimal Performance { get; set; }

        public int GoalsScored { get; set; }

        public int Wins { get; set; }

        public int Losses { get; set; }

        public int Draws { get; set; }
    }
}
