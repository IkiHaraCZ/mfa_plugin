// MfaTotpPoskytovatel.cs
using OtpNet;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Datona.Web.Code.Security
{
    public interface ITotpService
    {
        string GenerateSecret(int size = 20);
        string BuildOtpAuthUri(string issuer, string label, string secretBase32, int period = 30, int digits = 6);
        bool ValidateCode(string secret, string code);
        string FormatManualKey(string secretBase32);
        (string secret, string issuer, string label, int period, int digits) ParseMeta(string metaJson);
    }
    public sealed class MfaTotpPoskytovatel : ITotpService
    {
        public string GenerateSecret(int bytes = 20)
        {
            var b = new byte[bytes];
            RandomNumberGenerator.Fill(b);
            return Base32Encode(b);
        }

        public string BuildOtpAuthUri(string issuer, string label, string secretBase32, int digits, int period)
        {
            return $"otpauth://totp/{Uri.EscapeDataString(label)}?secret={secretBase32}&issuer={Uri.EscapeDataString(issuer)}&period={period}&digits={digits}";
        }

        public string FormatManualKey(string secretBase32)
        {
            var s = secretBase32.Replace(" ", "").ToUpperInvariant();
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (i > 0 && i % 4 == 0) sb.Append(' ');
                sb.Append(s[i]);
            }
            return sb.ToString();
        }

        public bool ValidateCode(string secretBase32, string code)
        {
            if (string.IsNullOrWhiteSpace(code)) return false;
            code = code.Trim(); // nikdy nepřevádět na číslo!
            if (code.Length < 6 || code.Length > 8) return false;
            foreach (var ch in code) if (ch < '0' || ch > '9') return false;

            var key = Base32Decode(secretBase32);
            const int period = 30;
            const int digits = 6;
            const int window = 1; // ±1 krok

            long timestep = GetUnixTimeStep(period);
            for (long offset = -window; offset <= window; offset++)
            {
                var expected = ComputeTotp(key, timestep + offset, digits);
                if (SecureEquals(expected, code)) return true;
            }
            return false;
        }

        public (string secret, string issuer, string label, int period, int digits) ParseMeta(string metaJson)
        {
            using var doc = JsonDocument.Parse(metaJson);
            var r = doc.RootElement;
            return (
                r.GetProperty("secret_p").GetString()!,
                r.GetProperty("issuer").GetString()!,
                r.GetProperty("label").GetString()!,
                r.GetProperty("period").GetInt32(),
                r.GetProperty("digits").GetInt32()
            );
        }

        public string BuildMetaJson(string secret, string issuer, string label, int period, int digits)
        {
            return JsonSerializer.Serialize(new { secret, issuer, label, period, digits });
        }

        // ---- helpers ----
        private static long GetUnixTimeStep(int period)
        {
            var seconds = (long)(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            return seconds / period;
        }

        private static string ComputeTotp(byte[] key, long timestep, int digits)
        {
            Span<byte> msg = stackalloc byte[8];
            for (int i = 7; i >= 0; i--)
            {
                msg[i] = (byte)(timestep & 0xFF);
                timestep >>= 8;
            }

            Span<byte> hash = stackalloc byte[20];
            using (var hmac = new HMACSHA1(key))
            {
                var full = hmac.ComputeHash(msg.ToArray());
                full.AsSpan().Slice(full.Length - 20, 20).CopyTo(hash); // HMACSHA1 vrací 20B
            }

            int offset = hash[hash.Length - 1] & 0x0F;
            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            int otp = binary % (int)Math.Pow(10, digits);
            return otp.ToString().PadLeft(digits, '0');
        }

        private static bool SecureEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            var result = 0;
            for (int i = 0; i < a.Length; i++)
                result |= a[i] ^ b[i];
            return result == 0;
        }

        private static string Base32Encode(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new StringBuilder();
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

        private static byte[] Base32Decode(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return Array.Empty<byte>();
            s = s.Trim().Replace(" ", "").Replace("=", "").ToUpperInvariant();
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            var bytes = new System.Collections.Generic.List<byte>(s.Length * 5 / 8);
            int bits = 0, value = 0;

            foreach (char c in s)
            {
                int idx = alphabet.IndexOf(c);
                if (idx < 0) continue; // ignoruj nevalidní znaky/spacery
                value = (value << 5) | idx;
                bits += 5;
                if (bits >= 8)
                {
                    bytes.Add((byte)((value >> (bits - 8)) & 0xFF));
                    bits -= 8;
                }
            }
            return bytes.ToArray();
        }
    }
}