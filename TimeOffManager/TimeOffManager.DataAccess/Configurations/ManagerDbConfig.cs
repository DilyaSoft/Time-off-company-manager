using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class ManagerDbConfig : IEntityTypeConfiguration<Manager>
    {
        public void Configure(EntityTypeBuilder<Manager> builder)
        {
            
            builder.HasMany(obj => obj.ManagerTimeOffs)
                .WithOne(x => x.ApproveManager).HasForeignKey(f => f.ManagerId);
        }
    }
}
