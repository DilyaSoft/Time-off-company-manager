using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class TeamDbConfig : IEntityTypeConfiguration<Team>
    {
        public void Configure(EntityTypeBuilder<Team> builder)
        {
            builder.HasMany(x => x.Employees)
                .WithOne(x => x.Team)
                .HasForeignKey(f => f.TeamId);
        }
    }
}
