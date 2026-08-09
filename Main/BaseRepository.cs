#nullable enable
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Threading;
using System.Threading.Tasks;

namespace Api.Main
{

    public abstract class BaseRepository
    {
        protected readonly MyCon _db;

        protected BaseRepository(MyCon dbConnection)
        {
            _db = dbConnection ?? throw new ArgumentNullException(nameof(dbConnection));
        }

        protected async Task<T?> ExecuteScalarAsync<T>(
            string sql,
            IEnumerable<DbParameter>? parameters = null,
            CommandType commandType = CommandType.Text,
            int? commandTimeoutSeconds = null,
            DbTransaction? transaction = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sql))
                throw new ArgumentException("SQL is required.", nameof(sql));

            await using var connection = _db.GetConnection();
            await using var command = PrepareCommand(connection, sql, commandType, commandTimeoutSeconds, transaction, parameters);

            await connection.OpenAsync(ct).ConfigureAwait(false);
            var result = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
            return SafeChangeType<T>(result);
        }

        protected async Task<int> ExecuteNonQueryAsync(
            string sql,
            IEnumerable<DbParameter>? parameters = null,
            CommandType commandType = CommandType.Text,
            int? commandTimeoutSeconds = null,
            DbTransaction? transaction = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sql))
                throw new ArgumentException("SQL is required.", nameof(sql));

            await using var connection = _db.GetConnection();
            await using var command = PrepareCommand(connection, sql, commandType, commandTimeoutSeconds, transaction, parameters);

            await connection.OpenAsync(ct).ConfigureAwait(false);
            return await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        protected async Task<List<T>> ExecuteReaderToListAsync<T>(
            string sql,
            Func<DbDataReader, T> mapper,
            IEnumerable<DbParameter>? parameters = null,
            CommandType commandType = CommandType.Text,
            int? commandTimeoutSeconds = null,
            DbTransaction? transaction = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sql))
                throw new ArgumentException("SQL is required.", nameof(sql));
            if (mapper is null)
                throw new ArgumentNullException(nameof(mapper));

            var list = new List<T>();

            await using var connection = _db.GetConnection();
            await using var command = PrepareCommand(connection, sql, commandType, commandTimeoutSeconds, transaction, parameters);

            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var reader = await command.ExecuteReaderAsync(CommandBehavior.CloseConnection, ct)
                                                  .ConfigureAwait(false);

            while (await reader.ReadAsync(ct).ConfigureAwait(false))
                list.Add(mapper(reader));

            return list;
        }

        protected async Task<DbTransaction> BeginTransactionAsync(
            IsolationLevel isolationLevel = IsolationLevel.ReadCommitted,
            CancellationToken ct = default)
        {
            var conn = _db.GetConnection();
            await conn.OpenAsync(ct).ConfigureAwait(false);
            return await conn.BeginTransactionAsync(isolationLevel, ct).ConfigureAwait(false);
        }

        protected DbParameter CreateParameter(
            string name,
            object? value,
            DbType? dbType = null,
            int? size = null,
            ParameterDirection direction = ParameterDirection.Input)
        {
            using var conn = _db.GetConnection();
            using var cmd = conn.CreateCommand();

            var p = cmd.CreateParameter();
            p.ParameterName = name;
            p.Value = value ?? DBNull.Value;
            p.Direction = direction;
            if (dbType.HasValue) p.DbType = dbType.Value;
            if (size.HasValue && size.Value > 0) p.Size = size.Value;

            return p;
        }

        private static DbCommand PrepareCommand(
            DbConnection connection,
            string sql,
            CommandType commandType,
            int? commandTimeoutSeconds,
            DbTransaction? transaction,
            IEnumerable<DbParameter>? parameters)
        {
            var command = connection.CreateCommand();
            command.CommandText = sql;
            command.CommandType = commandType;

            if (transaction != null)
                command.Transaction = transaction;

            if (commandTimeoutSeconds.HasValue && commandTimeoutSeconds.Value > 0)
                command.CommandTimeout = commandTimeoutSeconds.Value;

            if (parameters != null)
            {
                foreach (var p in parameters)
                {
                    var clone = command.CreateParameter();
                    clone.ParameterName = p.ParameterName;
                    clone.Value = p.Value;
                    clone.Direction = p.Direction;
                    clone.DbType = p.DbType;
                    clone.Size = p.Size;
                    command.Parameters.Add(clone);
                }
            }

            return command;
        }

        private static T? SafeChangeType<T>(object? value)
        {
            if (value is null || value is DBNull) return default;
            if (value is T t) return t;

            var targetType = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            return (T)Convert.ChangeType(value, targetType);
        }
    }
}