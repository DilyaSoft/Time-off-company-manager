namespace TimeOffManager.Core.DTO
{
    public record SignUpResult
    {
        public bool Success {  get; }
        public string? Message {  get; init; }
        public Token? Token { get; init; }
        private SignUpResult(bool success, string message, Token? token)
        {
            Success = success;
            Message = message;
            Token = token;
        }
        private SignUpResult(bool success, string message)
        {
            Success = success;
            Message = message;
        }
        
        public static SignUpResult Error(string message) => new SignUpResult( false, message);
        public static SignUpResult Ok(Token token) => new SignUpResult( true,"" ,token);
    }
}
