using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TimeOffManager.DataAccess.Models;

namespace TimeOffManager.DataAccess.Context
{
    public class DataContext : IdentityDbContext<User, CustomRole, int>
    {
        public DbSet<Employee> Employees { get; set; }
        public DbSet<Manager> Managers { get; set; }
        public DbSet<Team> Teams { get; set; }
        public DbSet<Company> Companies { get; set; }
        public DbSet<TimeOff> TimeOffs { get; set; }

        public DataContext(DbContextOptions<DataContext> options)
         : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(DataContext).Assembly);
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<CustomRole>().ToTable("CustomRoles");
        }
    }
}
