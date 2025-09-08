using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using QRCoder;

namespace Datona.Web.Controllers
{
    [AllowAnonymous]
    public class QrController : Controller
    {
        // GET /qr/otp?data=otpauth://...&size=240
        [HttpGet("qr/otp")]
        public IActionResult Otp([FromQuery] string data, [FromQuery] int size = 240)
        {
            if (string.IsNullOrWhiteSpace(data)) return BadRequest();

            using var gen = new QRCodeGenerator();
            using var q = gen.CreateQrCode(data, QRCodeGenerator.ECCLevel.M);
            using var png = new PngByteQRCode(q);

            int ppm = size <= 180 ? 4 : size <= 240 ? 6 : size <= 320 ? 8 : size <= 480 ? 10 : size <= 640 ? 12 : 14;
            var bytes = png.GetGraphic(ppm);

            Response.Headers["Cache-Control"] = "public,max-age=300";
            return File(bytes, "image/png");
        }
    }
}