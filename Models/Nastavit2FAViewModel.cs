using System.Collections.Generic;

namespace Datona.Web.Models
{
    public class Nastavit2FAViewModel
    {
        public string Email { get; set; }
        public string OtpKod { get; set; }
        public string OtpAuthUri { get; set; }
        public long MethodId { get; set; }
        public string ManualSecret { get; set; }
        public string Error { get; set; }
        public bool Success { get; set; }
        public List<string> BackupCodes { get; set; }
    }
}