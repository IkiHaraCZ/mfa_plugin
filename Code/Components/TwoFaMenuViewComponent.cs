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
                // .ASPXAUTH -> AuthenticationClaim -> loginentity_id
                var aspx = _http.HttpContext?.Request?.Cookies[".ASPXAUTH"];
                var ac = !string.IsNullOrWhiteSpace(aspx) ? AuthCookie.AuthenticationClaim(aspx) : null;
                if (ac == null)
                    return View(new TwoFaMenuVM { Has2FA = false, LoggedIn = false });

                var has = _store.HasAnyActiveMethodAsync(ac.LoginentityId).Result; // sync kvùli zbytku projektu
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