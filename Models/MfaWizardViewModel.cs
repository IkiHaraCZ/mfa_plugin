namespace Datona.Web.Models
{
    public sealed class MfaWizardViewModel
    {
        public long MethodId { get; set; }
        public string OtpAuthUri { get; set; } = string.Empty;
        public string ManualKey { get; set; } = string.Empty;
        public string UserLabel { get; set; } = string.Empty; // pro zobrazení (login)
        public bool IsActive { get; set; } = false;
    }
}