using Microsoft.EntityFrameworkCore;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class EmployeeDbConfig : IEntityTypeConfiguration<Employee>
    {
        public void Configure(Microsoft.EntityFrameworkCore.Metadata.Builders.EntityTypeBuilder<Employee> builder)
        {
            builder.HasMany(obj => obj.TimeOffs)
                .WithOne(obj => obj.Employee)
                .HasForeignKey(f => f.EmployeeId);
        }
    }
}
