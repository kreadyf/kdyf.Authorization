using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>
    /// <see cref="IUserSuspensionSource"/> and <see cref="IUserActivityRecorder"/> over <c>auth.UserProfile</c>. No row
    /// means an active person.
    /// </summary>
    /// <remarks>
    /// The last access is written in its own scope (its own context), never through the request's: a request that has
    /// changes pending must not have them saved by a read. At most one write per person every
    /// <see cref="AuthorizationStoreOptions.LastAccessInterval"/>, decided by the database, so several instances agree.
    /// </remarks>
    public sealed class EfUserProfileStore<TContext> : IUserSuspensionSource, IUserActivityRecorder where TContext : DbContext
    {
        private readonly TContext _db;
        private readonly IServiceScopeFactory _scopes;
        private readonly TimeProvider _time;
        private readonly TimeSpan _interval;

        public EfUserProfileStore(TContext db, IServiceScopeFactory scopes, IOptions<AuthorizationStoreOptions> options, TimeProvider? time = null)
        {
            _db = db;
            _scopes = scopes;
            _time = time ?? TimeProvider.System;
            _interval = options.Value.LastAccessInterval;
        }

        public Task<bool> IsSuspendedAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            var objectId = UserRole.Normalize(subjectId);
            return _db.Set<UserProfile>().AsNoTracking().AnyAsync(p => p.ObjectId == objectId && !p.IsActive, cancellationToken);
        }

        public async Task RecordAsync(UserIdentity user, CancellationToken cancellationToken = default)
        {
            if (_interval <= TimeSpan.Zero || string.IsNullOrWhiteSpace(user.SubjectId))
                return;

            var objectId = UserRole.Normalize(user.SubjectId);
            var now = _time.GetUtcNow().UtcDateTime;
            var due = now - _interval;

            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TContext>();
            var profiles = db.Set<UserProfile>();

            var updated = await profiles
                .Where(p => p.ObjectId == objectId && (p.LastLoginAt == null || p.LastLoginAt < due))
                .ExecuteUpdateAsync(s => s.SetProperty(p => p.LastLoginAt, now), cancellationToken);
            if (updated > 0 || await profiles.AnyAsync(p => p.ObjectId == objectId, cancellationToken))
                return;

            // First time seen: the profile appears, active. It grants nothing; access is still the group and the roles.
            profiles.Add(new UserProfile
            {
                ObjectId = objectId,
                Email = string.IsNullOrWhiteSpace(user.Email) ? null : user.Email.Trim().ToLowerInvariant(),
                IsActive = true,
                CreatedAt = now,
                LastLoginAt = now,
            });
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                // Another instance inserted it first: it has been seen, which is all this records.
            }
        }
    }

    public static class EfUserProfileExtensions
    {
        /// <summary>
        /// Suspension and the last access over <typeparamref name="TContext"/> (with
        /// <see cref="ModelBuilderExtensions.ApplyAuthorizationModel"/> applied, schema version 4).
        /// </summary>
        public static IServiceCollection AddEfUserProfiles<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            services.AddScoped<EfUserProfileStore<TContext>>();
            services.AddScoped<IUserSuspensionSource>(sp => sp.GetRequiredService<EfUserProfileStore<TContext>>());
            services.AddScoped<IUserActivityRecorder>(sp => sp.GetRequiredService<EfUserProfileStore<TContext>>());
            return services;
        }
    }
}
