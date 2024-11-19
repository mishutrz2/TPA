namespace TPA.Domain.Models
{
    public class MatchDayTeam
    {
        public Guid MatchDayId { get; set; }

        public MatchDay MatchDay { get; set; }

        public Guid TeamId { get; set; }

        public Team Team { get; set; }

        // navigation property for one-to-one from MatchDayTeam to MatchDayTeamPerformanceDetails
        public Guid? MatchDayTeamPerformanceDetailsId {  get; set; }

        public MatchDayTeamPerformanceDetails? MatchDayTeamPerformanceDetails { get; set; }
    }
}
