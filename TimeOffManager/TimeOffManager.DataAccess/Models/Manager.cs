namespace TimeOffManager.DataAccess.Models
{
    public class Manager : User
    {
        public IEnumerable<TimeOff> ManagerTimeOffs { get; set; }
        public int ManagerRoleId { get; set; }
        public bool IsExecutive { get; set; }
    }
}
