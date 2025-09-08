using System;
using System.Threading.Tasks;
using Datona.Web.Code;
using Datona.Web.Code.Security;
using Datona.MobilniCisnik.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Datona.Web.Components
{
    public sealed class TwoFaMenuViewComponent : ViewComponent
    {
        private readonly IMfaStore _store;
        private readonly GcrHelper _gcr;
        private readonly IHttpContextAccessor _http;

        public TwoFaMenuViewComponent(IMfaStore store, GcrHelper gcr, IHttpContextAccessor http)
        {
            _store = store;
            _gcr = gcr;
            _http = http;
        }

        public IViewComponentResult Invoke()
        {
            try
            {
                // .ASPXAUTH -> AuthenticationClaim -> GCR instance -> loginentity_id
                var aspx = _http.HttpContext?.Request?.Cookies[".ASPXAUTH"];
                var ac = !string.IsNullOrWhiteSpace(aspx) ? AuthCookie.AuthenticationClaim(aspx) : null;
                if (ac == null)
                    return View(new TwoFaMenuVM { Has2FA = false, LoggedIn = false });

                var inst = _gcr.Instance(new UserContext
                {
                    Login = ac.UserName,
                    HesloMD5 = ac.HesloMD5,
                    MacAddress = "00-0C-E3-24-5A-CC",
                    language_id = "1",
                    InstanceId = ac.InstanceId,
                    Guid_externi_db = ac.Guid_externi_db
                });
                if (inst == null)
                    return View(new TwoFaMenuVM { Has2FA = false, LoggedIn = false });

                var loginentityId = inst.GetLoginentityId();
                var has = _store.HasAnyActiveMethodAsync(loginentityId).Result; // sync kvùli zbytku projektu
                return View(new TwoFaMenuVM { Has2FA = has, LoggedIn = true });
            }
            catch
            {
                return View(new TwoFaMenuVM { Has2FA = false, LoggedIn = false });
            }
        }

        public sealed class TwoFaMenuVM
        {
            public bool LoggedIn { get; set; }
            public bool Has2FA { get; set; }
        }
    }
}