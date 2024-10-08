namespace TimeOffManager.Core.DTO
{
    public struct GetTimeOffsByUserRequest
    {
        public int UserId {  get; set; }
        public int[] Months { get; set; }
        public bool IsApproved {  get; set; }
        public int Year { get; set; }
    }
}
