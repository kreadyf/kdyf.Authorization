using System.Reflection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.Hosting
{
    /// <summary>
    /// What a host composes authorization with: the decisions that belong to its code, and the providers it plugs
    /// in — where roles and tokens are stored, who may use the application, how people sign in.
    /// </summary>
    /// <remarks>
    /// Implemented by kdyf.Authorization.AspNetCore. A provider package (kdyf.Authorization.EntityFrameworkCore,
    /// kdyf.Authorization.EntraId, …) adds an extension method that calls <see cref="AddProvider"/>, so the composition
    /// knows none of them: a host picks its database and its identity provider by the packages it references.
    /// </remarks>
    public interface IKdyfAuthorizationBuilder
    {
        /// <summary>
        /// Registers a provider. It runs once the host's decisions are all known (<see cref="KdyfAuthorizationProviderContext.DeclarationAssemblies"/>
        /// included), and before authorization reads them.
        /// </summary>
        /// <param name="name">The call that adds it (<c>UseEntityFrameworkStore</c>), for the error when it is added twice.</param>
        /// <param name="register">The registrations.</param>
        void AddProvider(string name, Action<KdyfAuthorizationProviderContext> register);
    }

    /// <summary>What a provider registers into.</summary>
    public sealed class KdyfAuthorizationProviderContext
    {
        /// <summary>Built by the composition.</summary>
        public KdyfAuthorizationProviderContext(
            IServiceCollection services,
            IConfiguration configuration,
            IConfigurationSection section,
            AuthenticationBuilder authentication,
            IReadOnlyList<Assembly> declarationAssemblies)
        {
            Services = services;
            Configuration = configuration;
            Section = section;
            Authentication = authentication;
            DeclarationAssemblies = declarationAssemblies;
        }

        /// <summary>The host's services.</summary>
        public IServiceCollection Services { get; }

        /// <summary>The host's whole configuration: connection strings live at its root.</summary>
        public IConfiguration Configuration { get; }

        /// <summary>The library's section (<c>KdyfAuthorization</c> unless the host named another one).</summary>
        public IConfigurationSection Section { get; }

        /// <summary>Where an identity provider adds the scheme people sign in with.</summary>
        public AuthenticationBuilder Authentication { get; }

        /// <summary>The assemblies holding the host's permissions and policies.</summary>
        public IReadOnlyList<Assembly> DeclarationAssemblies { get; }

        /// <summary>
        /// The authentication scheme people arrive with (the JWT bearer of the identity provider). Set by exactly one
        /// provider; personal access tokens are the composition's own.
        /// </summary>
        public string? UserScheme { get; private set; }

        /// <summary>Declares the scheme people arrive with. Only one provider may.</summary>
        public void SetUserScheme(string scheme)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
            if (UserScheme is not null && UserScheme != scheme)
                throw new InvalidOperationException(
                    $"Two identity providers declare how people sign in ('{UserScheme}' and '{scheme}'). Use one.");
            UserScheme = scheme;
        }
    }
}
