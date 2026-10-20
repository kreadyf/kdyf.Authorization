using kdyf.Authorization.Administration.Abstractions;
using System.Globalization;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// How a search term matches somebody from the directory.
    /// </summary>
    /// <remarks>
    /// It is a policy of its own, and not an inline check, because both rules here were bugs found
    /// against a real tenant: they look like details and they break the search outright.
    /// </remarks>
    public static class DirectoryUserFilter
    {
        /// <summary>
        /// Whether <paramref name="search"/> appears in the display name, the e-mail or the local part of the UPN,
        /// ignoring case and accents.
        /// </summary>
        public static bool Matches(DirectoryUser user, string search) =>
            Contains(user.DisplayName, search) ||
            Contains(user.Email, search) ||
            Contains(LocalPart(user.UserPrincipalName), search);

        /// <summary>
        /// The part of the UPN before the tenant domain.
        /// </summary>
        /// <remarks>
        /// Matching against the whole UPN makes any term that appears in the tenant domain hit
        /// EVERY user: a guest's UPN is 'person_domain.com#EXT#@tenant.onmicrosoft.com', so
        /// searching for a word contained in the tenant name returns the entire directory.
        /// </remarks>
        public static string? LocalPart(string? userPrincipalName)
        {
            if (string.IsNullOrEmpty(userPrincipalName))
                return userPrincipalName;

            var cut = userPrincipalName.IndexOf("#EXT#", StringComparison.OrdinalIgnoreCase);
            if (cut < 0)
                cut = userPrincipalName.IndexOf('@');

            return cut < 0 ? userPrincipalName : userPrincipalName[..cut];
        }

        /// <summary>
        /// Case- AND accent-insensitive: whoever types 'andres' must find 'Andrés', and 'muller'
        /// must find 'Müller'. An ordinal comparison returns nothing and reads as a broken search.
        /// </summary>
        private static bool Contains(string? value, string search) =>
            value is not null &&
            CultureInfo.InvariantCulture.CompareInfo.IndexOf(
                value, search, CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace) >= 0;
    }
}
