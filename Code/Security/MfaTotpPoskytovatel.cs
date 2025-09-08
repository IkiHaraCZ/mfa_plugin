using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Datona.Web.Code.Security
{
    public interface ITotpService
    {
        string GenerateSecret(int bytes = 20);
        string BuildOtpAuthUri(string issuer, string label, string secretBase32, int digits, int period);
        string FormatManualKey(string secretBase32);
        bool ValidateCode(string secretBase32, string code);
        byte[] BuildMetaPayload(string secret, string issuer, string label, int period, int digits);
        (string secret, string issuer, string label, int period, int digits) ParseMetaPayload(byte[] protectedData);
    }

    /// <summary>
    /// TOTP provider (RFC 6238). Base32 secret, otpauth URI (Google Key URI Format),
    /// základní validace s oknem ±1 kroku.
    /// </summary>
    public sealed class MfaTotpPoskytovatel : ITotpService
    {
        // --- Public API ---

        public string GenerateSecret(int bytes = 20)
        {
            var b = new byte[bytes];
            RandomNumberGenerator.Fill(b);
            return Base32Encode(b);
        }

        public string BuildOtpAuthUri(string issuer, string label, string secretBase32, int digits, int period)
        {
            // otpauth://totp/{label}?secret=...&issuer=...&period=...&digits=...
            // Google Key URI Format
            var encLabel = Uri.EscapeDataString(label ?? "");
            var encIssuer = Uri.EscapeDataString(issuer ?? "");
            return $"otpauth://totp/{encIssuer}:{encLabel}?secret={secretBase32}&issuer={encIssuer}&period={period}&digits={digits}";
        }

        public string FormatManualKey(string secretBase32)
        {
            // jen pro čitelné opsání – NEumožňuje zadat vlastní secret
            var s = (secretBase32 ?? string.Empty).Replace(" ", "").ToUpperInvariant();
            var sb = new StringBuilder(s.Length + s.Length / 4);
            for (int i = 0; i < s.Length; i++)
            {
                if (i > 0 && i % 4 == 0) sb.Append(' ');
                sb.Append(s[i]);
            }
            return sb.ToString();
        }

        public bool ValidateCode(string secretBase32, string code)
        {
            if (string.IsNullOrWhiteSpace(secretBase32) || string.IsNullOrWhiteSpace(code))
                return false;

            // standardně 30 s; číslice vezmeme z délky kódu (obvykle 6)
            int period = 30;
            int digits = Math.Clamp(code.Length, 6, 8);
            int window = 1; // povol ±1 krok

            var secret = Base32Decode(secretBase32);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var timestep = now / period;

            for (long w = -window; w <= window; w++)
            {
                var otp = ComputeTotp(secret, timestep + w, digits);
                if (TimingSafeEquals(code, otp))
                    return true;
            }
            return false;
        }
        public byte[] BuildMetaPayload(string secret, string issuer, string label, int period, int digits)
        {
            var json = JsonSerializer.Serialize(new
            {
                secret = secret ?? "",
                issuer = issuer ?? "",
                label = label ?? "",
                period,
                digits
            });
            return Encoding.UTF8.GetBytes(json);
        }

        public (string secret, string issuer, string label, int period, int digits) ParseMetaPayload(byte[] protectedData)
        {
            var json = Encoding.UTF8.GetString(protectedData ?? Array.Empty<byte>());
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;

            string secret = r.TryGetProperty("secret", out var p0) ? p0.GetString() ?? "" : "";
            string issuer = r.TryGetProperty("issuer", out var p1) ? p1.GetString() ?? "" : "";
            string label = r.TryGetProperty("label", out var p2) ? p2.GetString() ?? "" : "";
            int period = r.TryGetProperty("period", out var p3) ? p3.GetInt32() : 30;
            int digits = r.TryGetProperty("digits", out var p4) ? p4.GetInt32() : 6;

            return (secret, issuer, label, period, digits);
        }

        // --- Internals ---

        private static string ComputeTotp(byte[] key, long counter, int digits)
        {
            Span<byte> c = stackalloc byte[8];
            // big-endian
            for (int i = 7; i >= 0; i--)
            {
                c[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            Span<byte> hmac = stackalloc byte[20];
            using (var h = new HMACSHA1(key))
            {
                h.TryComputeHash(c, hmac, out _);
            }

            int offset = hmac[hmac.Length - 1] & 0x0F;
            int binCode = ((hmac[offset] & 0x7F) << 24)
                        | ((hmac[offset + 1] & 0xFF) << 16)
                        | ((hmac[offset + 2] & 0xFF) << 8)
                        | (hmac[offset + 3] & 0xFF);

            int mod = (int)Math.Pow(10, digits);
            int val = binCode % mod;
            return val.ToString(new string('0', digits));
        }

        private static bool TimingSafeEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        // Base32 (RFC 4648 bez paddingu) — pro TOTP secret stačí
        private static string Base32Encode(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new StringBuilder((data.Length * 8 + 4) / 5);
            int bits = 0, value = 0;
            foreach (var b in data)
            {
                value = (value << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    output.Append(alphabet[(value >> (bits - 5)) & 31]);
                    bits -= 5;
                }
            }
            if (bits > 0) output.Append(alphabet[(value << (5 - bits)) & 31]);
            return output.ToString();
        }

        private static byte[] Base32Decode(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return Array.Empty<byte>();
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            var s = input.Trim().Replace(" ", "").TrimEnd('=').ToUpperInvariant();
            int byteCount = s.Length * 5 / 8;
            byte[] result = new byte[byteCount];

            int buffer = 0, bitsLeft = 0, index = 0;
            foreach (char c in s)
            {
                int val = alphabet.IndexOf(c);
                if (val < 0) continue; // ignoruj nepovolené znaky (např. separátory)
                buffer = (buffer << 5) | val;
                bitsLeft += 5;
                if (bitsLeft >= 8)
                {
                    result[index++] = (byte)((buffer >> (bitsLeft - 8)) & 0xFF);
                    bitsLeft -= 8;
                    if (index == result.Length) break;
                }
            }
            return result;
        }
    }
}
