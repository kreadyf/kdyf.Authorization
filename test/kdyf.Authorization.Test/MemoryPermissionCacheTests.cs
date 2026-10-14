using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Caching;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace kdyf.Authorization.Test
{
    /// <summary>
    /// The cache belongs to the HOST, not to this package: it arrives injected and plays by the host's rules. These
    /// tests pin the part of that contract that is easy to break without noticing.
    /// </summary>
    [TestClass]
    public class MemoryPermissionCacheTests
    {
        private static readonly UserIdentity User = new(SubjectId: "oid-1", Email: "dev@example.com");

        /// <summary>
        /// A host that configures <c>SizeLimit</c> requires EVERY entry to declare its size, or
        /// <c>Set</c> throws. It really happened: the failure fires while RESOLVING permissions, so it does not
        /// degrade performance —it denies access with a 500 on every request—.
        /// </summary>
        [TestMethod]
        public async Task Stores_in_a_host_cache_with_SizeLimit()
        {
            var sut = Build(new MemoryCacheOptions { SizeLimit = 512 * 1024 * 1024 }, "Invoicing.Invoices");

            var permissions = await sut.GetPermissionsAsync(User);

            CollectionAssert.Contains(permissions.ToList(), "Invoicing.Invoices");
        }

        /// <summary>
        /// The empty set has its own duration —shorter— and goes down the same path: without a
        /// size of its own it would throw too, and precisely for the just-registered user.
        /// </summary>
        [TestMethod]
        public async Task Stores_an_empty_set_with_SizeLimit()
        {
            var sut = Build(new MemoryCacheOptions { SizeLimit = 1024 });

            var permissions = await sut.GetPermissionsAsync(User);

            Assert.AreEqual(0, permissions.Count);
        }

        /// <summary>With a limit, the entry is really stored: the second call does not go back to the store.</summary>
        [TestMethod]
        public async Task With_SizeLimit_the_entry_is_cached_all_the_same()
        {
            var inner = Store("Administration");
            var sut = new CachingPermissionStore(
                inner.Object,
                Cache(new MemoryCacheOptions { SizeLimit = 512 * 1024 * 1024 }));

            await sut.GetPermissionsAsync(User);
            await sut.GetPermissionsAsync(User);

            inner.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        private static CachingPermissionStore Build(MemoryCacheOptions options, params string[] codes) =>
            new(Store(codes).Object, Cache(options));

        private static MemoryPermissionCache Cache(MemoryCacheOptions options) =>
            new(new MemoryCache(options),
                new PermissionAuthorizationOptions(),
                NullLogger<MemoryPermissionCache>.Instance, TimeProvider.System);

        private static Mock<IPermissionStore> Store(params string[] codes)
        {
            var store = new Mock<IPermissionStore>();
            store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new HashSet<string>(codes, StringComparer.Ordinal));
            return store;
        }
    }
}
