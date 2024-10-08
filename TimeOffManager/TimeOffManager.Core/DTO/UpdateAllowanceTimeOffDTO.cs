namespace TimeOffManager.Core.DTO
{
    public struct UpdateAllowanceTimeOffDTO
    {
        public int UserId { get; set; }
        public int TotalTimeOff { get; set; }
        public int TookTimeOff { get; set; }
    }
}
