using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class TimeOffDbConfig : IEntityTypeConfiguration<TimeOff>
    {
        public void Configure(EntityTypeBuilder<TimeOff> builder)
        {
            builder.HasKey(obj => obj.Id);
            builder.HasOne(x => x.ApproveManager).WithMany(x => x.ManagerTimeOffs)
                .HasForeignKey(f => f.ApproverId).OnDelete(DeleteBehavior.NoAction);

            builder.HasOne(x => x.Employee).WithMany(x => x.TimeOffs).HasForeignKey(f => f.EmployeeId)
                .OnDelete(DeleteBehavior.NoAction);

            builder.Property(x => x.Type).IsRequired();
        }
    }
}
