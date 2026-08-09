using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;

namespace Api.Main
{
    public sealed class MyCon
    {
        private readonly string _connectionString;
        public int? DefaultCommandTimeoutSeconds { get; } = 30;

        private static (string server, string database, string userId, string password) LoadConfiguration()
        {
            string configFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "conn.env");
            if (!File.Exists(configFile))
                configFile = Path.Combine(Directory.GetCurrentDirectory(), "conn.env");
            if (!File.Exists(configFile))
                configFile = Path.Combine(Directory.GetCurrentDirectory(), "..", "conn.env");

            if (File.Exists(configFile))
            {
                var config = new Dictionary<string, string>();
                foreach (var line in File.ReadAllLines(configFile))
                {
                    if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                    {
                        var parts = line.Split('=', 2);
                        if (parts.Length == 2)
                            config[parts[0].Trim()] = parts[1].Trim();
                    }
                }
                return (
                    config.GetValueOrDefault("DB_SERVER", ""),
                    config.GetValueOrDefault("DB_DATABASE", ""),
                    config.GetValueOrDefault("DB_USER", ""),
                    config.GetValueOrDefault("DB_PASSWORD", "")
                );
            }
            else
            {
                return (
                    Environment.GetEnvironmentVariable("DB_SERVER") ?? "",
                    Environment.GetEnvironmentVariable("DB_DATABASE") ?? "",
                    Environment.GetEnvironmentVariable("DB_USER") ?? "",
                    Environment.GetEnvironmentVariable("DB_PASSWORD") ?? ""
                );
            }
        }

        public MyCon()
        {
            var config = LoadConfiguration();
            var server = config.server;
            uint port = 1433; 

            if (!string.IsNullOrWhiteSpace(server))
            {
                var parts = server.Split(':', 2);
                if (parts.Length == 2 && uint.TryParse(parts[1], out var parsedPort))
                {
                    server = parts[0];
                    port = parsedPort;
                }
            }

            var builder = new SqlConnectionStringBuilder
            {
                DataSource = $"{server},{port}",
                InitialCatalog = config.database,
                UserID = config.userId,
                Password = config.password,
                ConnectTimeout = 30,
                TrustServerCertificate = true
            };

            _connectionString = builder.ConnectionString;
        }

        public DbConnection GetConnection()
        {
            try
            {
                return new SqlConnection(_connectionString);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error creating SQL Server connection: {ex.Message}", ex);
            }
        }

        public async Task<bool> CanConnectAsync(CancellationToken ct = default)
        {
            await using var conn = GetConnection();
            try
            {
                await conn.OpenAsync(ct);
                return conn.State == ConnectionState.Open;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (conn.State == ConnectionState.Open)
                    await conn.CloseAsync();
            }
        }

        public DbCommand CreateCommand(DbConnection connection, string sql, CommandType type = CommandType.Text)
        {
            if (connection is null) throw new ArgumentNullException(nameof(connection));
            if (string.IsNullOrWhiteSpace(sql)) throw new ArgumentException("SQL is required.", nameof(sql));

            var cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.CommandType = type;
            if (DefaultCommandTimeoutSeconds.HasValue && DefaultCommandTimeoutSeconds.Value > 0)
                cmd.CommandTimeout = DefaultCommandTimeoutSeconds.Value;
            return cmd;
        }
    }
}