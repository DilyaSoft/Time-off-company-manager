using MimeKit;
using TimeOffManager.Core.Services.Interfaces;
using TimeOffManager.Core.Settings;

namespace TimeOffManager.Core.Services
{
    public class EmailService : IEmailService
    {
        public async Task Send(string to, string from, string message, string subject)
        {
            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
#pragma warning disable CA1031 // Do not catch general exception types
                try
                {
                    using var emailMessage = PrepareMessage(to, subject, message);
                    await client.ConnectAsync(SmtpSettings.Server, SmtpSettings.Port, true);
                    await client.AuthenticateAsync(SmtpSettings.Username, SmtpSettings.Password);
                    await client.SendAsync(emailMessage);
                    await client.DisconnectAsync(true);
                }
                catch (Exception ex)
                {

                }
#pragma warning restore CA1031 // Do not catch general exception types
            }
        }

        private MimeMessage PrepareMessage(string email, string subject, string message)
        {
            var emailMessage = new MimeMessage();

            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    emailMessage.From.Add(new MailboxAddress("TGramHunt admin panel", SmtpSettings.From));
                    emailMessage.To.Add(new MailboxAddress("", email));
                    emailMessage.Subject = subject;
                    emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
                    {
                        Text = message
                    };

                }
                catch (ArgumentNullException ex)
                {
                    throw new ArgumentNullException($"Couldn't compose an email to {email}.");
                }
            }

            return emailMessage;
        }
    }
}
