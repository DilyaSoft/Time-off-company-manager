using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class UserDbConfig : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.HasKey(obj => obj.Id);
            builder.Property(obj => obj.FirstName).IsRequired();
            builder.Property(obj => obj.LastName).IsRequired();
            builder.Property(obj => obj.Email).IsRequired();
            builder.HasOne(x => x.Team)
                .WithMany(x => x.Employees).HasForeignKey(x => x.TeamId);
        }
    }
}
