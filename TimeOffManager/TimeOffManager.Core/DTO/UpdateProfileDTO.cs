namespace TimeOffManager.Core.DTO
{
    public struct UpdateProfileDTO
    {
        public string FirstName {  get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public DateTime BirthDate { get; set; }
    }
}
