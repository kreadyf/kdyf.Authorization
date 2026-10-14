namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Cache of a user's effective permissions. The consumer invalidates it when an
    /// administrator changes roles or permissions; the TTL is only the safety net.
    /// </summary>
    /// <remarks>
    /// The default implementation uses IMemoryCache and is therefore NOT shared across instances:
    /// in a deployment with several replicas, invalidation only affects the one serving the call;
    /// on the others the permission stays alive until the TTL expires. Replace with a distributed
    /// implementation (Redis) if that window is unacceptable.
    /// </remarks>
    public interface IPermissionCache
    {
        /// <summary>Invalidates the cached permissions of a specific user.</summary>
        void Invalidate(UserIdentity user);

        /// <summary>Invalidates the whole cache. Needed when the permissions of a shared role change.</summary>
        void InvalidateAll();
    }
}
