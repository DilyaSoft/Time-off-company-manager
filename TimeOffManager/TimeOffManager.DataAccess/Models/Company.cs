using System.ComponentModel.DataAnnotations.Schema;

namespace TimeOffManager.DataAccess.Models
{
    public class Company
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public byte[]? Logo { get; set; }
        [NotMapped]
        public string? LogoBase64 { get; set; }
        
        public IEnumerable<Employee> Employees {get; set; }
    }
}
