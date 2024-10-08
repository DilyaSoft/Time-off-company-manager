using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;
using TimeOffManager.DataAccess.Enums;

namespace TimeOffManager.DataAccess.Models
{
    public class User : IdentityUser<int>
    {
        public int CompanyId { get; set; }
        public Company Company { get; set; }
        public string? JobTitle { get; set; }
        public string? Phone { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public InviteStatus InviteStatus { get; set; }
        public int TotalAllowanceTimeOffInYear { get; set; }
        public int TookAllowanceTimeOff { get; set; }
        public DateTime StartWorkDate { get; set; }
        public DateTime BirthDate { get; set; }
        public int? TeamId { get; set; }
        public Team? Team { get; set; }

        [NotMapped]
        public string RoleName { get; set; }
        public IEnumerable<TimeOff> TimeOffs { get; set; }
    }
}
