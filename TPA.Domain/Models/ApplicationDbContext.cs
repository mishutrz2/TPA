using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace TPA.Domain.Models
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options)
    {
        public DbSet<List> Lists { get; set; }
        public DbSet<Team> Teams { get; set; }
        public DbSet<MatchDay> MatchDays { get; set; }
        public DbSet<MatchDayTeamPerformanceDetails> MatchDayTeamPerformanceDetails { get; set; }
        public DbSet<UserList> UserLists { get; set; }
        public DbSet<UserTeam> UserTeams { get; set; }
        public DbSet<MatchDayTeam> MatchDayTeams { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<List>()
                .HasIndex(l => l.Name)
                .IsUnique(); // This enforces the unique constraint at the database level

            // many-to-many relationship USERS and LISTS
            modelBuilder.Entity<UserList>().HasKey(ul => new
            {
                ul.ApplicationUserId,
                ul.ListId
            });

            modelBuilder.Entity<UserList>()
                .HasOne(ul => ul.User)
                .WithMany(x => x.UserLists)
                .HasForeignKey(ul => ul.ListId);

            modelBuilder.Entity<UserList>()
                .HasOne(ul => ul.List)
                .WithMany(x => x.UserLists)
                .HasForeignKey(ul => ul.ApplicationUserId);

            // one-to-many relationship LISTS and MATCHDAYS
            modelBuilder.Entity<MatchDay>()
                .HasOne(m => m.List)
                .WithMany(l => l.MatchDays)
                .HasForeignKey(m => m.ListId);

            // many-to-many between TEAMS and MATCHDAYS
            modelBuilder.Entity<MatchDayTeam>()
                .HasKey(mt => new { mt.MatchDayId, mt.TeamId });

            modelBuilder.Entity<MatchDayTeam>()
                .HasOne(mt => mt.MatchDay)
                .WithMany(m => m.MatchDayTeams)
                .HasForeignKey(mt => mt.MatchDayId);

            modelBuilder.Entity<MatchDayTeam>()
                .HasOne(mt => mt.Team)
                .WithMany(t => t.MatchDayTeams)
                .HasForeignKey(mt => mt.TeamId);

            // many-to-many between TEAMS and USERS
            modelBuilder.Entity<UserTeam>()
                .HasKey(mt => new { mt.UserId, mt.TeamId });

            modelBuilder.Entity<UserTeam>()
                .HasOne(mt => mt.User)
                .WithMany(m => m.UserTeams)
                .HasForeignKey(mt => mt.UserId);

            modelBuilder.Entity<UserTeam>()
                .HasOne(mt => mt.Team)
                .WithMany(t => t.UserTeams)
                .HasForeignKey(mt => mt.TeamId);

            // many-to-many relationship between USERS and MATCHDAYS
            modelBuilder.Entity<ApplicationUser>()
                .HasMany(u => u.MatchDays)
                .WithMany(m => m.Players)
                .UsingEntity(j => j.ToTable("MatchDayPlayers")); // Optional: specify a custom junction table name

            // one-to-one relationship between MATCHDAYTEAM and MATCHDAYTEAMPERFORMANCEDETAILS
            modelBuilder.Entity<MatchDayTeamPerformanceDetails>()
                .HasKey(p => new { p.MatchDayId, p.TeamId }); // Match the composite key

            modelBuilder.Entity<MatchDayTeam>()
                .HasOne(m => m.MatchDayTeamPerformanceDetails)
                .WithOne(p => p.MatchDayTeam)
                .HasForeignKey<MatchDayTeamPerformanceDetails>(p => new { p.MatchDayId, p.TeamId }) // Composite foreign key
                .IsRequired(); // Enforce required relationship
        }
    }
}
