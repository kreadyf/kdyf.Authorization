using Microsoft.AspNetCore.Http;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Simulation;

namespace kdyf.Authorization.Administration
{
    /// <summary>
    /// Who is administering in the current request: the one way to obtain the <see cref="AdminActor"/> the
    /// administration services take.
    /// </summary>
    /// <remarks>
    /// The rules that keep the administration safe — nobody changes their own access, nobody hands out more than
    /// they hold, no change from a token or while simulating — are decided on the actor. Built by hand, with the
    /// wrong simulation claim for instance, a simulated request reads as the real person's and those rules let the
    /// change through. The library's endpoints and a host's own get it from here, so they cannot differ.
    /// </remarks>
    public interface IAdminActorAccessor
    {
        /// <summary>The actor of the current request, resolved once per request.</summary>
        /// <exception cref="InvalidOperationException">Outside a request.</exception>
        Task<AdminActor> GetAsync(CancellationToken cancellationToken = default);
    }

    /// <summary><see cref="IAdminActorAccessor"/> over the current <see cref="HttpContext"/>.</summary>
    internal sealed class HttpContextAdminActorAccessor : IAdminActorAccessor
    {
        private readonly IHttpContextAccessor _http;
        private readonly IPrincipalPermissionResolver _permissions;
        private readonly IUserIdentityResolver _identities;
        private readonly UserSimulationOptions? _simulation;
        private Task<AdminActor>? _actor;

        public HttpContextAdminActorAccessor(
            IHttpContextAccessor http,
            IPrincipalPermissionResolver permissions,
            IUserIdentityResolver identities,
            UserSimulationOptions? simulation = null)
        {
            _http = http;
            _permissions = permissions;
            _identities = identities;
            _simulation = simulation;
        }

        // Scoped: one per request, so the first resolution is the one every later call sees — "may they call this"
        // and "may they hand this out" are never answered across a cache expiry.
        public Task<AdminActor> GetAsync(CancellationToken cancellationToken = default)
        {
            var user = _http.HttpContext?.User
                       ?? throw new InvalidOperationException("IAdminActorAccessor is only available inside a request.");

            return _actor ??= _permissions.ResolveActorAsync(user, _identities, _simulation, cancellationToken);
        }
    }
}
