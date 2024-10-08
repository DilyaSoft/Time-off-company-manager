namespace TimeOffManager.DataAccess.Models
{
    public class Team
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        
        public IEnumerable<User> Employees { get; set; }
    }
}
