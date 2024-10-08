namespace TimeOffManager.Core.DTO
{
    public struct AcceptInviteDto
    {
        public string ResetToken {  get; set; }
        public string Email { get; set; }
        public string NewPassword { get; set; }
        public DateTime BirthDate { get; set; }
        public string JobTitle { get; set; }
    }
}
