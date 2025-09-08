using Datona.MobilniCisnik.Web.Code;
using Datona.Web.Code;
using Datona.Web.Code.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Datona.Web.Models
{
    public class LoginViewModel
    {
        public string Login { get; set; }
        public string Heslo { get; set; }
        public string Error { get; set; }
        public string ReturnUrl { get; set; } = "/List/Home";
        public long? InstanceId { get; set; }

        public List<Instance> Instance = new List<Instance>();
        public List<Reseni> Reseni = new List<Reseni>();
        private GcrHelper gcrmc1;

        public string Language_id { get; set; } = "1";

        public string Guid_externi_db { get; set; }
        public LoginViewModel(GcrHelper gcrmc1, List<Reseni> Reseni1)
        {
            Instance = new List<Instance>();
            Reseni = Reseni1; //KoupitDataLayer.VratReseni(gcrmc1, false);
        }
        public LoginViewModel()
        {
            Instance = new List<Instance>();
        }

        public bool Show2FAModal { get; set; }

        public string TwoFAError { get; set; } = "";
    }
}
