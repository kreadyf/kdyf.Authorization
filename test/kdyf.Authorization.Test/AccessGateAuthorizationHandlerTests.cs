using System.Security.Claims;
using kdyf.Authorization;
using kdyf.Authorization.Abstractions;
using kdyf.Authorization.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace kdyf.Authorization.Test
{
    /// <summary>
    /// The gate the fallback and default policies demand: a token of the tenant is not enough, the caller must hold something.
    /// </summary>
    [TestClass]
    public class AccessGateAuthorizationHandlerTests
    {
        private const string Email = "dev@example.com";

        private Mock<IPermissionStore> _store = null!;
        private PermissionAuthorizationOptions _options = null!;

        [TestInitialize]
        public void Setup()
        {
            _store = new Mock<IPermissionStore>();
            _options = new PermissionAuthorizationOptions();
        }

        [TestMethod]
        public async Task A_person_holding_a_permission_passes()
        {
            StoreReturns("Compliance.Cases");

            Assert.IsTrue((await Evaluate(Person())).HasSucceeded);
        }

        /// <summary>Outside the group, suspended, or a member with no role and no base access: the store answers nothing.</summary>
        [TestMethod]
        public async Task A_person_holding_nothing_is_refused()
        {
            StoreReturns();

            Assert.IsFalse((await Evaluate(Person())).HasSucceeded);
        }

        [TestMethod]
        public async Task A_store_failure_refuses()
        {
            _store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("down"));

            Assert.IsFalse((await Evaluate(Person())).HasSucceeded);
        }

        [TestMethod]
        public async Task An_anonymous_caller_is_refused_without_reading_the_store()
        {
            Assert.IsFalse((await Evaluate(new ClaimsPrincipal(new ClaimsIdentity()))).HasSucceeded);
            _store.Verify(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        /// <summary>A personal access token carries its permissions as role claims.</summary>
        [TestMethod]
        public async Task A_token_carrying_a_permission_passes()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "Compliance.Cases") }, "PAT"));

            Assert.IsTrue((await Evaluate(principal)).HasSucceeded);
        }

        /// <summary>Any application of the tenant can get a token with no role: that is not being let in.</summary>
        [TestMethod]
        public async Task An_application_token_without_roles_is_refused()
        {
            StoreReturns();
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("oid", "6a1a2ce1-0000-0000-0000-0000000000ff"), new Claim("idtyp", "app") }, "Bearer"));

            Assert.IsFalse((await Evaluate(principal)).HasSucceeded);
        }

        [TestMethod]
        public async Task A_token_with_no_role_and_no_identity_is_refused()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("name", "Someone") }, "Bearer"));

            Assert.IsFalse((await Evaluate(principal)).HasSucceeded);
            _store.Verify(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        /// <summary>A person's role claims are the directory's, not the application's: only the store lets them in.</summary>
        [TestMethod]
        public async Task A_person_is_not_let_in_by_a_role_claim()
        {
            StoreReturns();
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("email", Email), new Claim(ClaimTypes.Role, "Compliance.Cases") }, "Bearer"));

            Assert.IsFalse((await Evaluate(principal)).HasSucceeded);
        }

        [TestMethod]
        public async Task Role_claims_do_not_count_when_they_are_not_accepted()
        {
            _options.AcceptRoleClaims = false;
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "Compliance.Cases") }, "PAT"));

            Assert.IsFalse((await Evaluate(principal)).HasSucceeded);
        }

        private void StoreReturns(params string[] permissions) =>
            _store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new HashSet<string>(permissions, StringComparer.Ordinal));

        private static ClaimsPrincipal Person() =>
            new(new ClaimsIdentity(new[] { new Claim("email", Email) }, authenticationType: "Bearer"));

        private async Task<AuthorizationHandlerContext> Evaluate(ClaimsPrincipal principal)
        {
            var handler = new AccessGateAuthorizationHandler(
                _store.Object,
                new ClaimsUserIdentityResolver(_options),
                _options,
                NullLogger<AccessGateAuthorizationHandler>.Instance);

            var context = new AuthorizationHandlerContext(new[] { AccessGateRequirement.Instance }, principal, resource: null);
            await handler.HandleAsync(context);
            return context;
        }
    }
}
