namespace TimeOffManager.Core.DTO
{
    public record SignInResult
    {
        public bool Success {  get; }
        public string Message {  get; init; }
        public Token? Token { get; init; }

        private SignInResult(bool success, string message, Token? token)
        {
            Success = success;
            Message = message;
            Token = token;
        }

        public static SignInResult Ok(Token token) => new SignInResult(true, "", token);
        public static SignInResult Error(string message) => new SignInResult(false, message, null);

    }
}
