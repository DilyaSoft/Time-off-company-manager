using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Configurations
{
    public class CompanyDbConfig : IEntityTypeConfiguration<Company>
    {
        public void Configure(EntityTypeBuilder<Company> builder)
        {
            builder.HasKey(obj => obj.Id);
            builder.HasMany(obj => obj.Employees).
                WithOne(obj => obj.Company).HasForeignKey(f => f.CompanyId);
        }
    }
}
