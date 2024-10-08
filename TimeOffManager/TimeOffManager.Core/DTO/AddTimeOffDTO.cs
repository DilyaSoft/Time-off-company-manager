using TimeOffManager.DataAccess.Enums;

namespace TimeOffManager.Core.DTO
{
    public struct AddTimeOffDto
    {
        public int TeamId { get; set; }
        public RequestType Type { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public string Note { get; set; }
        public int EmployeeId { get; set; }
    }
}
