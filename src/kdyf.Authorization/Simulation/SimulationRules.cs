using kdyf.Authorization.Authorization;

namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Who may simulate, and whom — written once, for every simulated request, for starting a simulation and for
    /// listing who can be simulated, so the list never offers a person a request would then refuse.
    /// </summary>
    public static class SimulationRules
    {
        /// <summary>A caller without an e-mail and an immutable id: a non-person client (a PAT, an application token).</summary>
        public const string InteractiveSignInOnly = "Simulation is only available to an interactive sign-in.";

        /// <summary>The refusal of a simulation of somebody who holds more than the caller.</summary>
        public const string CannotSimulateWhoHoldsMore = "You cannot simulate a user who holds permissions you do not hold.";

        /// <summary>Why a person is not a candidate: they hold something the caller does not. Fit to show next to them.</summary>
        public const string HoldsMore = "Holds permissions you do not hold.";

        /// <summary>The refusal of a caller who does not hold the simulation permission.</summary>
        public static string RequiresPermission(string permission) => $"Simulating another user requires {permission}.";

        /// <summary>
        /// What the person holds that the caller does not. "Covers", not a subset test, so whoever holds a wildcard covers
        /// every code it stands for.
        /// </summary>
        /// <remarks>
        /// Read-only is not enough on its own: a caller holding only the simulation permission could otherwise borrow an
        /// administrator and read everything the administrator's menu opens.
        /// </remarks>
        public static IReadOnlyList<string> HeldBeyond(IEnumerable<string> borrowed, IReadOnlySet<string> held)
        {
            ArgumentNullException.ThrowIfNull(borrowed);
            ArgumentNullException.ThrowIfNull(held);
            return borrowed.Where(code => !PermissionWildcards.Covers(held, code)).ToList();
        }

        /// <summary>Whether the person holds anything the caller does not: see <see cref="HeldBeyond"/>.</summary>
        public static bool HoldsMoreThan(IEnumerable<string> borrowed, IReadOnlySet<string> held) =>
            HeldBeyond(borrowed, held).Count > 0;
    }
}
