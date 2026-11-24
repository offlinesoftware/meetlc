using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace mlc.Server;

internal sealed record UserAccount(string Username);

internal sealed class UserStore(
    string databasePath,
    IPasswordHasher<UserAccount> passwordHasher)
{
    private readonly IPasswordHasher<UserAccount> _passwordHasher = passwordHasher;

    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = databasePath,
        Mode = SqliteOpenMode.ReadWriteCreate
    }.ToString();

    public async Task InitializeAsync(string? tomPassword, string? mariePassword)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                CREATE TABLE IF NOT EXISTS Users (
                    Username TEXT PRIMARY KEY COLLATE NOCASE,
                    PasswordHash TEXT NOT NULL
                );
                """;
            await command.ExecuteNonQueryAsync();
        }

        await EnsureUserAsync(connection, "tom", tomPassword);
        await EnsureUserAsync(connection, "marie", mariePassword);
    }

    public async Task<UserAccount?> AuthenticateAsync(string username, string password)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Username, PasswordHash FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        var user = new UserAccount(reader.GetString(0));
        var verification = _passwordHasher.VerifyHashedPassword(user, reader.GetString(1), password);
        return verification == PasswordVerificationResult.Failed ? null : user;
    }

    private async Task EnsureUserAsync(SqliteConnection connection, string username, string? password)
    {
        await using var existsCommand = connection.CreateCommand();
        existsCommand.CommandText = "SELECT 1 FROM Users WHERE Username = $username;";
        existsCommand.Parameters.AddWithValue("$username", username);

        if (await existsCommand.ExecuteScalarAsync() is not null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 12)
        {
            throw new InvalidOperationException(
                $"Set MEETLC_INITIAL_PASSWORD_{username.ToUpperInvariant()} to a password of at least 12 characters to create the {username} account.");
        }

        var user = new UserAccount(username);
        var passwordHash = _passwordHasher.HashPassword(user, password);

        await using var insertCommand = connection.CreateCommand();
        insertCommand.CommandText = "INSERT INTO Users (Username, PasswordHash) VALUES ($username, $passwordHash);";
        insertCommand.Parameters.AddWithValue("$username", username);
        insertCommand.Parameters.AddWithValue("$passwordHash", passwordHash);
        await insertCommand.ExecuteNonQueryAsync();
    }
}
