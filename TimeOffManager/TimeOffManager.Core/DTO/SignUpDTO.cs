namespace TimeOffManager.Core.DTO
{
    public struct SignUpDTO
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime BirthDate { get; set; }
        public string? JobTitle {  get; set; }
    }
}
