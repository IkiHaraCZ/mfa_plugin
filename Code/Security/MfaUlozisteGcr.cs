using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Npgsql;

namespace Datona.Web.Code.Security
{
    public sealed class MfaUlozisteGcr : IMfaStore
    {
        private readonly GcrHelper _gcrHelper;
        private readonly IHttpContextAccessor _http;

        // --- Konstanty pro nové číselníky ---
        private const int TYP_TOTP = 1;           // dade.mfa_metody_typy: totp
        private const int ST_ZALOZENO = 1;        // pending
        private const int ST_ZASLANO = 2;        // pending (např. pro jiné metody)
        private const int ST_AKTIVNI = 3;
        private const int ST_ZRUSENO = 4;

        public MfaUlozisteGcr(GcrHelper gcrHelper, IHttpContextAccessor http)
        {
            _gcrHelper = gcrHelper;
            _http = http;
        }

        // ---------- IMfaStore ----------

        // „nejnovější pending“ = stav ZALOZENO nebo ZASLANO
        public Task<UserMfaMethod?> GetLatestPendingTotpAsync(long userId) =>
            Task.FromResult(FirstOrDefault(ExecTable(
                @$"SELECT *
                   FROM dade.mfa_metody2loginentity
                   WHERE loginentity_id=@u
                     AND mfa_metody_typy_id={TYP_TOTP}
                     AND mfa_status_ciselnik_id IN ({ST_ZALOZENO},{ST_ZASLANO})
                   ORDER BY mfa_metody2loginentity_id DESC
                   LIMIT 1",
                P("u", userId))));

        public Task<UserMfaMethod?> GetActiveTotpAsync(long userId) =>
            Task.FromResult(FirstOrDefault(ExecTable(
                @$"SELECT *
                   FROM dade.mfa_metody2loginentity
                   WHERE loginentity_id=@u
                     AND mfa_metody_typy_id={TYP_TOTP}
                     AND mfa_status_ciselnik_id={ST_AKTIVNI}
                   ORDER BY mfa_metody2loginentity_id ASC
                   LIMIT 1",
                P("u", userId))));

        public Task<long> CreatePendingTotpAsync(long userId, string metaJson)
        {
            // naposledy_pouzito je NOT NULL => hned nastavíme na now()
            var id = ExecScalar(
                @"INSERT INTO dade.mfa_metody2loginentity
                    (loginentity_id, mfa_metody_typy_id, mfa_status_ciselnik_id, meta_json, naposledy_pouzito)
                  VALUES
                    (@u, @typ, @st, @m, @t)
                  RETURNING mfa_metody2loginentity_id",
                P("u", userId),
                P("typ", TYP_TOTP),
                P("st", ST_ZALOZENO),
                PJ("m", metaJson),
                P("t", DateTime.Now)      // TIMESTAMP bez TZ
            );
            return Task.FromResult(Convert.ToInt64(id));
        }

        public Task ActivateMethodAsync(long methodId)
        {
            ExecNonQuery(
                @"UPDATE dade.mfa_metody2loginentity
                    SET mfa_status_ciselnik_id=@st
                  WHERE mfa_metody2loginentity_id=@id",
                P("st", ST_AKTIVNI), P("id", methodId));
            return Task.CompletedTask;
        }

        public Task SetMethodLastUsedAsync(long methodId, DateTime when)
        {
            ExecNonQuery(
                @"UPDATE dade.mfa_metody2loginentity
                    SET naposledy_pouzito=@t
                  WHERE mfa_metody2loginentity_id=@id",
                P("t", when), P("id", methodId));
            return Task.CompletedTask;
        }

        public Task RemoveUnusedBackupCodesAsync(long userId)
        {
            // v novém schématu: „zrušíme“ nepoužité tím, že nastavíme platny=false
            ExecNonQuery(
                @"UPDATE dade.mfa_zalozni_kody
                    SET platny=false
                  WHERE loginentity_id=@u
                    AND pouzito IS NULL
                    AND platny=true",
                P("u", userId));
            return Task.CompletedTask;
        }

        public Task InsertBackupCodesAsync(long userId, IEnumerable<string> hashed)
        {
            foreach (var h in hashed)
            {
                ExecNonQuery(
                    @"INSERT INTO dade.mfa_zalozni_kody(loginentity_id, code_hash)
                      VALUES(@u, @h)",
                    P("u", userId), P("h", h));
            }
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<BackupCode>> GetUnusedBackupCodesAsync(long userId)
        {
            var dt = ExecTable(
                @"SELECT mfa_zalozni_kody_id, loginentity_id, code_hash, vytvoreno, platnost_do, pouzito, platny
                  FROM dade.mfa_zalozni_kody
                  WHERE loginentity_id=@u AND pouzito IS NULL AND platny=true",
                P("u", userId));
            var list = dt.Rows.Cast<DataRow>().Select(MapBackup).ToList();
            return Task.FromResult<IReadOnlyList<BackupCode>>(list);
        }

        public Task MarkBackupCodeUsedAsync(long backupId, DateTime when)
        {
            ExecNonQuery(
                @"UPDATE dade.mfa_zalozni_kody
                    SET pouzito=@t, platny=false
                  WHERE mfa_zalozni_kody_id=@id",
                P("t", when), P("id", backupId));
            return Task.CompletedTask;
        }

        public Task InsertAuditAsync(long? userId, string action, string? ip, string? ua, object? details)
        {
            // No-op: audit tabulka v aktuálně dodaném schématu není.
            // Nechávám prázdné, ať to neláme build.
            return Task.CompletedTask;
        }

        public Task<bool> HasAnyActiveMethodAsync(long userId)
        {
            var v = ExecScalar(
                @$"SELECT mfa_metody2loginentity_id
                   FROM dade.mfa_metody2loginentity
                   WHERE loginentity_id=@u
                     AND mfa_status_ciselnik_id={ST_AKTIVNI}
                   LIMIT 1",
                P("u", userId));
            return Task.FromResult(v != null);
        }

        public Task<int> RevokeAllMethodsAsync(long userId)
        {
            var rows = ExecNonQuery(
                @"UPDATE dade.mfa_metody2loginentity
                    SET mfa_status_ciselnik_id=@st
                  WHERE loginentity_id=@u
                    AND mfa_status_ciselnik_id<>@st",
                P("st", ST_ZRUSENO), P("u", userId));
            return Task.FromResult(rows);
        }

        public Task<int> DeleteAllBackupCodesAsync(long userId)
        {
            var rows = ExecNonQuery(
                @"UPDATE dade.mfa_zalozni_kody
                    SET platny=false
                  WHERE loginentity_id=@u
                    AND platny=true",
                P("u", userId));
            return Task.FromResult(rows);
        }

        // ---------- DB přístup přes GCR ----------

        private Datona.Web.Code.GcrInstance GetGcr()
        {
            var aspx = _http.HttpContext?.Request?.Cookies[".ASPXAUTH"];
            var ac = !string.IsNullOrEmpty(aspx) ? Datona.MobilniCisnik.Server.AuthCookie.AuthenticationClaim(aspx) : null;

            if (ac != null)
            {
                var uc = new Datona.Web.Code.UserContext
                {
                    Login = ac.UserName,
                    HesloMD5 = ac.HesloMD5,
                    MacAddress = "00-0C-E3-24-5A-CC",
                    language_id = "1",
                    InstanceId = ac.InstanceId,
                    Guid_externi_db = ac.Guid_externi_db
                };
                var inst = _gcrHelper.Instance(uc);
                if (inst != null) return inst;
            }
            return _gcrHelper.PublicInstance();
        }

        private DataTable ExecTable(string sql, params NpgsqlParameter[] ps)
        {
            var gcr = GetGcr();
            return gcr.select(PrepareSql(sql, ps));
        }

        private object ExecScalar(string sql, params NpgsqlParameter[] ps)
        {
            var gcr = GetGcr();
            return gcr.ExecuteScalar(sql, ps);
        }

        private int ExecNonQuery(string sql, params NpgsqlParameter[] ps)
        {
            var gcr = GetGcr();
            gcr.ExecuteNonQuery(sql, ps);
            return 0;
        }

        // ---------- Parametry & mapování ----------

        private static NpgsqlParameter P(string name, object value) => new(name, value ?? DBNull.Value);
        private static NpgsqlParameter PJ(string name, object? json)
        {
            var p = new NpgsqlParameter(name, NpgsqlTypes.NpgsqlDbType.Jsonb) { Value = json ?? DBNull.Value };
            return p;
        }

        private static UserMfaMethod? FirstOrDefault(DataTable dt) => dt.Rows.Count == 0 ? null : MapMethod(dt.Rows[0]);

        private static UserMfaMethod MapMethod(DataRow r) => new UserMfaMethod
        {
            // mapování na nové názvy
            Id = Convert.ToInt64(r["mfa_metody2loginentity_id"]),
            UserId = Convert.ToInt64(r["loginentity_id"]),
            Type = (MfaMethodType)Convert.ToInt32(r["mfa_metody_typy_id"]),          // 1 = TOTP
            Status = (MfaStatus)Convert.ToInt32(r["mfa_status_ciselnik_id"]),          // 1..4 dle číselníku
            CreatedAt = Convert.ToDateTime(r["vytvoreno"]),                                // TIMESTAMP NOT NULL
            LastUsedAt = Convert.ToDateTime(r["naposledy_pouzito"]),                        // TIMESTAMP NOT NULL
            MetaJson = Convert.ToString(r["meta_json"]) ?? "{}"
        };

        private static BackupCode MapBackup(DataRow r) => new BackupCode
        {
            Id = Convert.ToInt64(r["mfa_zalozni_kody_id"]),
            UserId = Convert.ToInt64(r["loginentity_id"]),
            CodeHash = Convert.ToString(r["code_hash"]) ?? "",
            CreatedAt = Convert.ToDateTime(r["vytvoreno"]),
            UsedAt = r["pouzito"] == DBNull.Value ? (DateTime?)null : Convert.ToDateTime(r["pouzito"])
        };

        // ---------- PrepareSql (pro GCR.select) ----------

        private static string PrepareSql(string sql, params NpgsqlParameter[] ps)
        {
            if (string.IsNullOrEmpty(sql) || ps == null || ps.Length == 0)
                return sql;

            var ordered = ps.Where(p => p != null)
                            .OrderByDescending(p => (p.ParameterName ?? string.Empty).Length)
                            .ToArray();

            string result = sql;

            foreach (var p in ordered)
            {
                var name = p.ParameterName;
                if (string.IsNullOrWhiteSpace(name)) continue;

                var token = "@" + name;
                var pattern = $@"(?<![A-Za-z0-9_]){Regex.Escape(token)}(?![A-Za-z0-9_])";
                var replacement = ToSqlLiteral(p);
                result = Regex.Replace(result, pattern, replacement);
            }
            return result;
        }

        private static string ToSqlLiteral(NpgsqlParameter p)
        {
            if (p.Value == null || p.Value == DBNull.Value) return "NULL";

            if (p.NpgsqlDbType == NpgsqlTypes.NpgsqlDbType.Jsonb)
            {
                var json = p.Value?.ToString() ?? "{}";
                return $"'{EscapeSql(json)}'::jsonb";
            }

            var v = p.Value;

            if (v is string s) return $"'{EscapeSql(s)}'";
            if (v is bool b) return b ? "true" : "false";

            switch (v)
            {
                case sbyte or byte or short or ushort or int or uint or long or ulong:
                    return Convert.ToString(v, CultureInfo.InvariantCulture);
                case float f: return f.ToString(CultureInfo.InvariantCulture);
                case double d: return d.ToString(CultureInfo.InvariantCulture);
                case decimal m: return m.ToString(CultureInfo.InvariantCulture);
            }

            if (v is DateTime dt)
            {
                // TIMESTAMP bez TZ
                var iso = dt.ToString("yyyy-MM-dd HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
                return $"'{iso}'";
            }

            if (v is DateTimeOffset dto)
            {
                var iso = dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fffffff", CultureInfo.InvariantCulture);
                return $"'{iso}'";
            }

            if (v is Guid g) return $"'{g:D}'";

            if (v is byte[] bytes && bytes.Length > 0)
            {
                var hex = BitConverter.ToString(bytes).Replace("-", string.Empty);
                return $"'\\x{hex}'::bytea";
            }

            return $"'{EscapeSql(v.ToString() ?? string.Empty)}'";
        }

        private static string EscapeSql(string s) => s.Replace("'", "''");
    }
}