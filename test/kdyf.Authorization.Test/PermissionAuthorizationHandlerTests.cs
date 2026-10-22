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
    /// The tests that matter are the denial ones: a failure here grants undue access.
    /// </summary>
    [TestClass]
    public class PermissionAuthorizationHandlerTests
    {
        private const string Permission = "Compliance.Cases";
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
        public async Task Grants_when_the_user_has_the_permission()
        {
            StoreReturns(Permission, "Order.Invoices");

            var context = await Evaluate(AuthenticatedUser(email: Email));

            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Denies_when_the_user_does_not_have_the_permission()
        {
            StoreReturns("Order.Invoices");

            var context = await Evaluate(AuthenticatedUser(email: Email));

            Assert.IsFalse(context.HasSucceeded);
        }

        /// <summary>A node held covers the codes below it, even from a store that does not expand.</summary>
        [TestMethod]
        public async Task Grants_when_the_user_holds_a_node_above_the_permission()
        {
            StoreReturns("Compliance");

            Assert.IsTrue((await Evaluate(AuthenticatedUser(email: Email))).HasSucceeded);
        }

        [TestMethod]
        public async Task Grants_when_the_user_holds_the_root()
        {
            StoreReturns(PermissionHierarchy.Root);

            Assert.IsTrue((await Evaluate(AuthenticatedUser(email: Email))).HasSucceeded);
        }

        /// <summary>The cut is by segment: 'Comp' is not above 'Compliance.Cases', nor is a sibling area.</summary>
        [TestMethod]
        public async Task Denies_when_the_user_holds_only_a_sibling_or_a_prefix()
        {
            StoreReturns("Comp", "Order", "Compliance.Cases.Archive");

            Assert.IsFalse((await Evaluate(AuthenticatedUser(email: Email))).HasSucceeded);
        }

        /// <summary>A token's role claim naming a node covers the codes below it, as a stored grant does.</summary>
        [TestMethod]
        public async Task Grants_through_a_role_claim_naming_a_node()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "Compliance") }, "PAT"));

            Assert.IsTrue((await Evaluate(principal)).HasSucceeded);
        }

        [TestMethod]
        public async Task Denies_when_the_user_does_not_exist_in_the_store()
        {
            StoreReturns();   // empty set: user not registered

            var context = await Evaluate(AuthenticatedUser(email: "unknown@example.com"));

            Assert.IsFalse(context.HasSucceeded);
        }

        /// <summary>
        /// Fail-closed: if the DB is down nothing is granted. It is the most important test in the package.
        /// </summary>
        [TestMethod]
        public async Task Denies_when_the_store_throws()
        {
            _store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("DB down"));

            var context = await Evaluate(AuthenticatedUser(email: Email));

            Assert.IsFalse(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Denies_when_the_request_is_anonymous()
        {
            StoreReturns(Permission);

            var context = await Evaluate(new ClaimsPrincipal(new ClaimsIdentity()));   // unauthenticated

            Assert.IsFalse(context.HasSucceeded);
            _store.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Never,
                "an anonymous request must not even get as far as querying the store");
        }

        [TestMethod]
        public async Task Denies_when_the_token_carries_no_identity_claims()
        {
            StoreReturns(Permission);

            // Authenticated, but without 'oid' or any email claim.
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("name", "Someone") }, "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsFalse(context.HasSucceeded);
        }

        /// <summary>
        /// PATs and application tokens: they are not people, they are not in the store, and they get in through the role claim.
        /// </summary>
        [TestMethod]
        public async Task Grants_through_role_claim_without_querying_the_store()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Role, Permission) }, "PAT"));

            var context = await Evaluate(principal);

            Assert.IsTrue(context.HasSucceeded);
            _store.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        /// <summary>
        /// A PERSON cannot sneak in through the role claim: if they could, whoever had a directory app role
        /// named after a permission would bypass the store — and with it, IsActive
        /// and role revocation, which is exactly what this system exists to guarantee.
        /// </summary>
        [TestMethod]
        public async Task The_role_claim_does_not_serve_a_person_the_store_rules()
        {
            StoreReturns();   // the user was deactivated / their roles were removed

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[]
                {
                    new Claim("email", Email),                 // it is a person
                    new Claim(ClaimTypes.Role, Permission)     // ...with a directory app role
                },
                "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsFalse(context.HasSucceeded, "the store said no: the role claim cannot override it");
            _store.Verify(
                s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()),
                Times.Once,
                "a person must always be resolved against the store");
        }

        /// <summary>
        /// A person without an e-mail claim is still a person: a v1 token whose 'upn' the JWT handler mapped, or a user
        /// without a mail. What makes it a person is that it was issued for a user (delegated scopes, mapped or not, or
        /// idtyp = user) — so their directory app role still cannot get them in past the store.
        /// </summary>
        [DataTestMethod]
        [DataRow("scp", "access_as_user")]
        [DataRow("http://schemas.microsoft.com/identity/claims/scope", "access_as_user")]
        [DataRow("idtyp", "user")]
        public async Task A_user_token_without_an_email_is_still_a_person(string claim, string value)
        {
            StoreReturns();   // the store says no

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[]
                {
                    new Claim("http://schemas.microsoft.com/identity/claims/objectidentifier", "6a1a2ce1-0000-0000-0000-000000000001"),
                    new Claim(claim, value),
                    new Claim(ClaimTypes.Role, Permission),
                },
                "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsFalse(context.HasSucceeded, "the role claim cannot override the store");
            _store.Verify(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        /// <summary>A v1 token mapped by the JWT handler carries the e-mail as ClaimTypes.Upn.</summary>
        [TestMethod]
        public void The_mapped_upn_is_read_as_the_email()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("oid", "6a1a2ce1-0000-0000-0000-000000000001"), new Claim(ClaimTypes.Upn, "Ana@Test") }, "Bearer"));

            Assert.AreEqual("ana@test", new ClaimsUserIdentityResolver(new PermissionAuthorizationOptions()).Resolve(principal)!.Email);
        }

        /// <summary>
        /// One person, one cache entry: an object id in upper case (a personal access token typed by hand) resolves to the
        /// key the store uses, so invalidating the person reaches it.
        /// </summary>
        [TestMethod]
        public void An_object_id_resolves_to_the_key_the_store_uses()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("oid", " 6A1A2CE1-0000-0000-0000-00000000000F ") }, "PAT"));

            var identity = new ClaimsUserIdentityResolver(new PermissionAuthorizationOptions()).Resolve(principal)!;

            Assert.AreEqual("6a1a2ce1-0000-0000-0000-00000000000f", identity.SubjectId);
            Assert.AreEqual("6a1a2ce1-0000-0000-0000-00000000000f", identity.CacheKey);
        }

        /// <summary>An application token (client credentials) has an object id but no scopes: it keeps using its role claims.</summary>
        [TestMethod]
        public async Task An_application_token_with_an_object_id_still_gets_in_through_its_role_claim()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("oid", "6a1a2ce1-0000-0000-0000-0000000000ff"), new Claim("idtyp", "app"), new Claim(ClaimTypes.Role, Permission) }, "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsTrue(context.HasSucceeded);
            _store.Verify(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [TestMethod]
        public async Task The_role_claim_serves_a_person_if_explicitly_enabled()
        {
            _options.AcceptRoleClaimsForUserPrincipals = true;
            StoreReturns();

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("email", Email), new Claim(ClaimTypes.Role, Permission) }, "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Ignores_the_role_claim_when_AcceptRoleClaims_is_disabled()
        {
            _options.AcceptRoleClaims = false;
            StoreReturns();

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Role, Permission), new Claim("email", Email) }, "Bearer"));

            var context = await Evaluate(principal);

            Assert.IsFalse(context.HasSucceeded);
        }

        [TestMethod]
        public async Task The_email_is_normalized_to_lowercase_before_querying()
        {
            UserIdentity? captured = null;
            _store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .Callback<UserIdentity, CancellationToken>((u, _) => captured = u)
                .ReturnsAsync(new HashSet<string>());

            await Evaluate(AuthenticatedUser(email: "Dev@Example.COM"));

            Assert.IsNotNull(captured);
            Assert.AreEqual(Email, captured!.Email);
        }

        // --- OR: an endpoint shared by several screens ---

        [TestMethod]
        public async Task Or_grants_if_they_have_the_first()
        {
            StoreReturns("Compliance.List");

            var context = await Evaluate(
                AuthenticatedUser(Email),
                "Compliance.List", "Compliance.Cases");

            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Or_grants_if_they_have_the_second()
        {
            StoreReturns("Compliance.Cases");

            var context = await Evaluate(
                AuthenticatedUser(Email),
                "Compliance.List", "Compliance.Cases");

            Assert.IsTrue(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Or_denies_if_they_have_neither()
        {
            StoreReturns("Order.Invoices");

            var context = await Evaluate(
                AuthenticatedUser(Email),
                "Compliance.List", "Compliance.Cases");

            Assert.IsFalse(context.HasSucceeded);
        }

        [TestMethod]
        public async Task Or_also_works_with_the_role_claim()
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Role, "Compliance.Cases") }, "PAT"));

            var context = await Evaluate(principal, "Compliance.List", "Compliance.Cases");

            Assert.IsTrue(context.HasSucceeded);
        }

        // --- helpers ---

        private void StoreReturns(params string[] permissions) =>
            _store
                .Setup(s => s.GetPermissionsAsync(It.IsAny<UserIdentity>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new HashSet<string>(permissions, StringComparer.Ordinal));

        private static ClaimsPrincipal AuthenticatedUser(string email) =>
            new(new ClaimsIdentity(new[] { new Claim("email", email) }, authenticationType: "Bearer"));

        private async Task<AuthorizationHandlerContext> Evaluate(
            ClaimsPrincipal principal,
            params string[] requiredCodes)
        {
            var handler = new PermissionAuthorizationHandler(
                _store.Object,
                new ClaimsUserIdentityResolver(_options),
                _options,
                NullLogger<PermissionAuthorizationHandler>.Instance);

            var codes = requiredCodes.Length > 0 ? requiredCodes : new[] { Permission };

            var context = new AuthorizationHandlerContext(
                new[] { new PermissionRequirement(codes) },
                principal,
                resource: null);

            await handler.HandleAsync(context);

            return context;
        }
    }
}
