using System.Globalization;

namespace TimeOffManager.Core.Settings
{
    public static class SmtpSettings
    {
        public static string? Server = "smtp.gmail.com";
            //get
            // => Environment.GetEnvironmentVariable("SmtpServer") ?? "";
        public static int Port
        {
            get
                => int.Parse(Environment.GetEnvironmentVariable("SmtpPort") ?? "0", CultureInfo.InvariantCulture);
        }
        public static string? Username
        {
            get
                => Environment.GetEnvironmentVariable("SmtpUserName") ?? "";
        }
        public static string? From
        {
            get => Environment.GetEnvironmentVariable("SmtpFrom") ?? "";
        }
        public static string? Password
        {
            get
                => Environment.GetEnvironmentVariable("SmtpPassword") ?? "";
        }
        public static bool EnableSsl
        {
            get => bool.Parse(Environment.GetEnvironmentVariable("SmtpSSLEnable") ?? "false");
        }
        public static int Timeout
        {
            get
                => int.Parse(Environment.GetEnvironmentVariable("SmtpTimeout") ?? "0", CultureInfo.InvariantCulture);
        }
    }
}
