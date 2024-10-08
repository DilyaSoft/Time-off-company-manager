using TimeOffManager.DataAccess.Enums;

namespace TimeOffManager.DataAccess.Models
{
    public class TimeOff
    {
        public int Id { get; set; }
        public RequestType Type { get; set; }
        public DateTime ApprovedDate {  get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public bool IsApproved { get; set; }
        public string Note { get; set; }
        public int? ManagerId { get; set; }
        public Manager? Manager { get; set; }
        public int EmployeeId { get; set; }
        public Employee? Employee { get; set; }
        public int ApproverId { get; set; }
        public Manager ApproveManager { get; set; }
    }
}
