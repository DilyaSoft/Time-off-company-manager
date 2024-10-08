namespace TimeOffManager.Core.Services.Interfaces
{
    public interface IEmailService
    {
        public Task Send(string to, string from, string message, string subject);
    }
}
