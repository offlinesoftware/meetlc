# meetlc

A Blazor WebAssembly app hosted by an ASP.NET Core server. The server stores user accounts in SQLite and handles password verification and cookie-based login sessions.

## Run locally

Set initial passwords for the two seeded users, then start the server:

```sh
export MEETLC_INITIAL_PASSWORD_TOM='a-unique-password-of-at-least-12-characters'
export MEETLC_INITIAL_PASSWORD_MARIE='another-unique-password-of-at-least-12-characters'
dotnet run --project Server/mlc.Server.csproj
```

Open the server URL printed by `dotnet run` and sign in as `tom` or `marie`. On first startup, the server creates `Server/App_Data/meetlc.db` and hashes each password before storing it. The environment variables are only used when creating a missing account; changing them later does not change an existing password. The SQLite database is excluded from version control.
