namespace TimeOffManager.Core.DTO
{
    public struct SendInviteDto
    {
        public string FirstName {  get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public int TeamId { get; set; }
    }
}
