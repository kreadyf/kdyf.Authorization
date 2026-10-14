using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Caching;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace kdyf.Authorization.Test
{
    [TestClass]
    public class CachingPermissionStoreTests
    {
        private static readonly UserIdentity User = new(SubjectId: "oid-1", Email: "dev@example.com");
        private static readonly UserIdentity Other = new(SubjectId: "oid-2", Email: "other@example.com");

        private Mock<IPermissionStore> _inner = null!;
        private MemoryPermissionCache _cache = null!;
        private CachingPermissionStore _sut = null!;

        [TestInitialize]
        public void Setup()
        {
            _inner = new Mock<IPermissionStore>();
            _inner
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new HashSet<string> { "Compliance.Cases" });

            _cache = new MemoryPermissionCache(
                new MemoryCache(new MemoryCacheOptions()),
                new PermissionAuthorizationOptions(),
                NullLogger<MemoryPermissionCache>.Instance, TimeProvider.System);

            _sut = new CachingPermissionStore(_inner.Object, _cache);
        }

        [TestMethod]
        public async Task The_second_call_does_not_hit_the_store()
        {
            await _sut.GetPermissionsAsync(User);
            await _sut.GetPermissionsAsync(User);

            _inner.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        [TestMethod]
        public async Task After_invalidating_the_user_it_is_queried_again()
        {
            await _sut.GetPermissionsAsync(User);

            _cache.Invalidate(User);
            await _sut.GetPermissionsAsync(User);

            _inner.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2));
        }

        [TestMethod]
        public async Task Invalidating_one_user_does_not_affect_the_others()
        {
            await _sut.GetPermissionsAsync(User);
            await _sut.GetPermissionsAsync(Other);

            _cache.Invalidate(User);
            await _sut.GetPermissionsAsync(Other);   // still cached

            _inner.Verify(
                s => s.GetPermissionsAsync(Other, It.IsAny<CancellationToken>()),
                Times.Once);
        }

        /// <summary>
        /// Changing the permissions of a shared role forces dropping the whole cache.
        /// </summary>
        [TestMethod]
        public async Task InvalidateAll_purges_every_user()
        {
            await _sut.GetPermissionsAsync(User);
            await _sut.GetPermissionsAsync(Other);

            _cache.InvalidateAll();

            await _sut.GetPermissionsAsync(User);
            await _sut.GetPermissionsAsync(Other);

            _inner.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Exactly(4));
        }

        /// <summary>
        /// Several concurrent requests from the same user, with an empty cache, share a SINGLE
        /// resolution. Without this, every call made while a screen starts up would hit the DB and Graph.
        /// </summary>
        [TestMethod]
        public async Task Concurrent_requests_from_the_same_user_resolve_only_once()
        {
            // The store blocks until it is released: that way the three requests overlap in flight.
            var gate = new TaskCompletionSource();
            var calls = 0;
            _inner
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .Returns(async () =>
                {
                    Interlocked.Increment(ref calls);
                    await gate.Task;
                    return (IReadOnlySet<string>)new HashSet<string> { "Compliance.Cases" };
                });

            var first = _sut.GetPermissionsAsync(User);
            var second = _sut.GetPermissionsAsync(User);
            var third = _sut.GetPermissionsAsync(User);

            gate.SetResult();
            await Task.WhenAll(first, second, third);

            Assert.AreEqual(1, calls, "the three concurrent requests must share a single resolution");
        }

        /// <summary>
        /// The same, as a host runs it: the store is created PER REQUEST (it wraps scoped services), only the cache
        /// is shared. Concurrent requests, each with its own store, still share a single resolution — the in-flight
        /// ones live in the cache, not in the store.
        /// </summary>
        [TestMethod]
        public async Task Concurrent_requests_with_a_store_each_resolve_only_once()
        {
            var gate = new TaskCompletionSource();
            var calls = 0;
            _inner
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .Returns(async () =>
                {
                    Interlocked.Increment(ref calls);
                    await gate.Task;
                    return (IReadOnlySet<string>)new HashSet<string> { "Compliance.Cases" };
                });

            var requests = Enumerable.Range(0, 3)
                .Select(_ => new CachingPermissionStore(_inner.Object, _cache).GetPermissionsAsync(User))
                .ToList();

            gate.SetResult();
            await Task.WhenAll(requests);

            Assert.AreEqual(1, calls, "a store per request must not mean a resolution per request");
            await new CachingPermissionStore(_inner.Object, _cache).GetPermissionsAsync(User);
            Assert.AreEqual(1, calls, "and the result is cached for the next request");
        }

        /// <summary>
        /// A store failure is not cached: if it were stored as "no permissions", the user
        /// would stay locked out for the whole TTL even if the DB recovers instantly. It travels with a fixed
        /// message — the store's own, which can name the server or its login, stays inside for the log.
        /// </summary>
        [TestMethod]
        public async Task A_store_failure_is_not_cached()
        {
            _inner
                .SetupSequence(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("Login failed for user 'app_dev'."))
                .ReturnsAsync(new HashSet<string> { "Compliance.Cases" });

            var error = await Assert.ThrowsExceptionAsync<AccessUnavailableException>(
                () => _sut.GetPermissionsAsync(User));
            Assert.AreEqual(AccessUnavailableException.Reason, error.Message);
            Assert.IsInstanceOfType(error.InnerException, typeof(InvalidOperationException), "the original stays inside, for the log");

            var permissions = await _sut.GetPermissionsAsync(User);

            CollectionAssert.Contains(permissions.ToList(), "Compliance.Cases");
        }
    }
}
