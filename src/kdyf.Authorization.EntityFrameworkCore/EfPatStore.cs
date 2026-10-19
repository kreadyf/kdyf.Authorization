using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// <see cref="IPatStore"/> implementation against a <typeparamref name="TContext"/> that has
    /// <see cref="ModelBuilderExtensions.ApplyAuthorizationModel"/> applied.
    /// </summary>
    /// <remarks>
    /// A token grants what ITS OWNER can do right now: its permissions are the owner's, resolved through
    /// the SAME <see cref="IPermissionStore"/> that authorizes the owner's own requests — the access
    /// group, the owner's roles, wildcard expansion and the cache. So a token can never outlive its
    /// owner's access: take the owner out of the group, remove their role or disable their account, and
    /// the token stops working within the same window as the owner's session does.
    /// </remarks>
    public sealed class EfPatStore<TContext> : IPatStore where TContext : DbContext
    {
        // Last-used is recorded at most once per this interval, to avoid an UPDATE
        // on every request from high-frequency integrations.
        private static readonly TimeSpan LastUsedThrottle = TimeSpan.FromMinutes(5);

        private readonly TContext _db;
        private readonly IPermissionStore _permissions;
        private readonly IServiceScopeFactory? _scopes;

        /// <param name="db">The request's context: only read.</param>
        /// <param name="permissions">The owner's permissions.</param>
        /// <param name="scopes">
        /// Where the last use is written: a context of its own, so a request with changes pending never has them saved by
        /// a token check. Without it, the request's context is used.
        /// </param>
        public EfPatStore(TContext db, IPermissionStore permissions, IServiceScopeFactory? scopes = null)
        {
            _db = db;
            _permissions = permissions;
            _scopes = scopes;
        }

        public async Task<PatPrincipal?> ResolveAsync(byte[] tokenHash, CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            var pat = await _db.Set<PersonalAccessToken>()
                .AsNoTracking()
                .Where(t => t.TokenHash == tokenHash
                         && t.IsActive
                         && (t.ExpiresAt == null || t.ExpiresAt > now))
                .Select(t => new { t.PersonalAccessTokenId, t.Name, t.LastUsedAt, t.OwnerObjectId })
                .FirstOrDefaultAsync(cancellationToken);

            if (pat is null)
                return null;

            // The owner's permissions, by their immutable id. A failure propagates: the handler turns
            // it into "PAT store error", never into a grant.
            var effective = await _permissions.GetPermissionsAsync(
                new UserIdentity(pat.OwnerObjectId, null), cancellationToken);

            // Owner without access (no role, disabled, gone from the directory): the token grants
            // nothing, so it is not valid. Returning a principal with zero permissions would leave it
            // "authenticated but unable to do anything", which muddles the diagnosis.
            if (effective.Count == 0)
                return null;

            // The token's own last use. Not the owner's last sign-in: a token is an integration, not the person.
            await TouchLastUsedAsync(pat.PersonalAccessTokenId, pat.LastUsedAt, now, cancellationToken);

            return new PatPrincipal(pat.Name, effective);
        }

        /// <summary>
        /// Records the last use (throttled). Best-effort: a write failure must NEVER deny a
        /// valid token, so any exception is swallowed.
        /// </summary>
        private async Task TouchLastUsedAsync(int patId, DateTime? lastUsedAt, DateTime now, CancellationToken ct)
        {
            if (lastUsedAt is not null && lastUsedAt > now - LastUsedThrottle)
                return;

            try
            {
                // Read and saved, not ExecuteUpdate: its signature differs between EF Core 8 and 10, and these packages run
                // on both.
                using var scope = _scopes?.CreateScope();
                var db = scope?.ServiceProvider.GetRequiredService<TContext>() ?? _db;
                var token = await db.Set<PersonalAccessToken>().FirstOrDefaultAsync(t => t.PersonalAccessTokenId == patId, ct);
                if (token is null || (token.LastUsedAt is not null && token.LastUsedAt > now - LastUsedThrottle))
                    return;
                token.LastUsedAt = now;
                await db.SaveChangesAsync(ct);
                if (scope is null)
                    db.Entry(token).State = EntityState.Detached;
            }
            catch
            {
                // best-effort: usage auditing does not block authentication.
            }
        }
    }

    public static class EfPatStoreExtensions
    {
        /// <summary>
        /// Registers <see cref="IPatStore"/> against the given <typeparamref name="TContext"/>
        /// (which must have <see cref="ModelBuilderExtensions.ApplyAuthorizationModel"/> applied).
        /// Needs an <see cref="IPermissionStore"/>: the owner's permissions come from it.
        /// </summary>
        public static IServiceCollection AddEfPatStore<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            services.AddScoped<IPatStore, EfPatStore<TContext>>();
            return services;
        }
    }
}
