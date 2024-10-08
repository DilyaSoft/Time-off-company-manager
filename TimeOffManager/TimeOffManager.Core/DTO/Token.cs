namespace TimeOffManager.Core.DTO
{
    public class Token
    {
        public double ExpireIn { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
