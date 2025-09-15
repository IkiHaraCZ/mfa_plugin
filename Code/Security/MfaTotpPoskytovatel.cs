// MfaTotpPoskytovatel.cs
using Microsoft.AspNetCore.DataProtection;
using OtpNet;
using System;
using System.Collections.Generic;
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
        string BuildMetaJson(string secret, string issuer, string label, int period, int digits);
    }
    public sealed class MfaTotpPoskytovatel : ITotpService
    {
        public string GenerateSecret(int bytes = 20)
        {
            var b = new byte[bytes];
            RandomNumberGenerator.Fill(b);  //přesuneme do sql
            return Base32Encoding.ToString(b);
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

            var key = Base32Encoding.ToBytes(secretBase32);
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
                r.GetProperty("secret").GetString()!,
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
    }

    public interface IBackupCodeService
    {
        (List<string> plain, List<string> hashed) GenerateBatch(int count = 10);
        bool Verify(string plain, string hash);
    }

    public sealed class MfaZalozniKody : IBackupCodeService
    {
        public (List<string> plain, List<string> hashed) GenerateBatch(int count = 10)
        {
            var plain = new List<string>(count);
            var hashed = new List<string>(count);

            for (int i = 0; i < count; i++)
            {
                var code = GenerateCode();
                plain.Add(code);
                hashed.Add(BCrypt.Net.BCrypt.HashPassword(code));
            }
            return (plain, hashed);
        }

        public bool Verify(string plain, string hash) => BCrypt.Net.BCrypt.Verify(plain ?? "", hash ?? "");

        private static string GenerateCode()
        {
            const string A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            Span<char> raw = stackalloc char[12];
            for (int i = 0; i < raw.Length; i++)
                raw[i] = A[RandomNumberGenerator.GetInt32(A.Length)];

            // formát XXXX-XXXX-XXXX
            return string.Create(14, raw.ToArray(), (dst, src) =>
            {
                dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3]; dst[4] = '-';
                dst[5] = src[4]; dst[6] = src[5]; dst[7] = src[6]; dst[8] = src[7]; dst[9] = '-';
                dst[10] = src[8]; dst[11] = src[9]; dst[12] = src[10]; dst[13] = src[11];
            });
        }
    }

    public interface ISecretProtector
    {
        string Protect(byte[] plaintext);
        byte[] Unprotect(string protectedBase64);
    }

    public sealed class MfaOchranaTajemstvi : ISecretProtector
    {
        private readonly IDataProtector _dp;
        public MfaOchranaTajemstvi(IDataProtectionProvider provider)
        {
            _dp = provider.CreateProtector("twofa/secrets/v1");
        }

        public string Protect(byte[] plaintext) => Convert.ToBase64String(_dp.Protect(plaintext));

        public byte[] Unprotect(string protectedBase64) => _dp.Unprotect(Convert.FromBase64String(protectedBase64 ?? ""));
    }
}