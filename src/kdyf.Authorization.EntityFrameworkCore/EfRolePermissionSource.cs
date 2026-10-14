using kdyf.Authorization.Abstractions;
using kdyf.Authorization.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary><see cref="IRolePermissionSource"/> over <c>auth.Role</c> and <c>auth.RolePermission</c>.</summary>
    public sealed class EfRolePermissionSource<TContext> : IRolePermissionSource where TContext : DbContext
    {
        private readonly TContext _db;

        public EfRolePermissionSource(TContext db) => _db = db;

        public async Task<IReadOnlyDictionary<string, IReadOnlySet<string>>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var roles = await _db.Set<Role>().AsNoTracking().Select(r => r.RoleValue).ToListAsync(cancellationToken);

            var grants = (await _db.Set<RolePermission>()
                    .AsNoTracking()
                    .Select(r => new { r.RoleValue, r.PermissionCode })
                    .ToListAsync(cancellationToken))
                .ToLookup(r => r.RoleValue, r => r.PermissionCode, StringComparer.Ordinal);

            // Every role, including one that grants nothing yet: it exists, and can be given to people.
            return roles.ToDictionary(
                role => role,
                role => (IReadOnlySet<string>)grants[role].ToHashSet(StringComparer.Ordinal),
                StringComparer.Ordinal);
        }
    }

    /// <summary><see cref="IUserRoleSource"/> over <c>auth.UserRole</c>.</summary>
    public sealed class EfUserRoleSource<TContext> : IUserRoleSource where TContext : DbContext
    {
        private readonly TContext _db;

        public EfUserRoleSource(TContext db) => _db = db;

        public async Task<IReadOnlySet<string>> GetRolesAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            var objectId = UserRole.Normalize(subjectId);

            var roles = await _db.Set<UserRole>()
                .AsNoTracking()
                .Where(r => r.ObjectId == objectId)
                .Select(r => r.RoleValue)
                .ToListAsync(cancellationToken);

            return roles.ToHashSet(StringComparer.Ordinal);
        }
    }

    public static class EfRoleSourceExtensions
    {
        /// <summary>
        /// Registers the roles of the access model over <typeparamref name="TContext"/> (which must have
        /// <see cref="ModelBuilderExtensions.ApplyAuthorizationModel"/> applied): <see cref="IRolePermissionSource"/>
        /// (which roles exist and what each grants) and <see cref="IUserRoleSource"/> (who holds which).
        /// </summary>
        public static IServiceCollection AddEfRoles<TContext>(this IServiceCollection services)
            where TContext : DbContext
        {
            services.AddScoped<IRolePermissionSource, EfRolePermissionSource<TContext>>();
            services.AddScoped<IUserRoleSource, EfUserRoleSource<TContext>>();
            return services;
        }
    }
}
