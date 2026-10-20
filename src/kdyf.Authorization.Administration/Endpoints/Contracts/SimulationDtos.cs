using kdyf.Authorization.Administration.Models;

namespace kdyf.Authorization.Administration.Endpoints.Contracts
{
    // The wire contract of the simulation endpoints. Kept apart from the service's models so the JSON a client reads
    // changes only when this file does.

    /// <summary>Body of <c>POST {prefix}/start</c>: who to read the application as.</summary>
    internal class StartSimulationRequestDto
    {
        /// <summary>Required in the body: without it the body cannot be read (400). Empty or malformed: 422 on <c>email</c>.</summary>
        public required string? Email { get; init; }
    }

    /// <summary>Body of <c>POST {prefix}/end</c>: whose simulation ends.</summary>
    internal class EndSimulationRequestDto
    {
        /// <inheritdoc cref="StartSimulationRequestDto.Email"/>
        public required string? Email { get; init; }
    }

    /// <summary>One side of a session.</summary>
    internal class SimulationUserDto
    {
        public string? ObjectId { get; init; }
        public string? Email { get; init; }
    }

    /// <summary>Who the session is for — the real and the effective user, always apart.</summary>
    internal class SimulationContextDto
    {
        /// <summary>True while the session is served as somebody else.</summary>
        public bool IsSimulating { get; init; }

        /// <summary>Who actually signed in: the administrator during a simulation.</summary>
        public required SimulationUserDto RealUser { get; init; }

        /// <summary>Whose permissions and data the session is served with.</summary>
        public required SimulationUserDto EffectiveUser { get; init; }

        /// <summary>True when the server refuses every write in this session.</summary>
        public bool ReadOnly { get; init; }
    }

    /// <summary>A person with access, and whether the caller may simulate them — with why not.</summary>
    internal class SimulationCandidateDto
    {
        public required string ObjectId { get; init; }

        /// <summary>What to start the simulation with.</summary>
        public string? Email { get; init; }

        public string? Name { get; init; }

        /// <summary>True when <c>POST {prefix}/start</c> would accept this person.</summary>
        public bool CanSimulate { get; init; }

        /// <summary>Why not, when <see cref="CanSimulate"/> is false. Fit to show.</summary>
        public string? Reason { get; init; }
    }

    /// <summary>A simulation just started, and how to keep it going.</summary>
    internal class SimulationStartedDto
    {
        /// <summary>The session as it will be on the next request that carries the header.</summary>
        public required SimulationContextDto Context { get; init; }

        /// <summary>Send this header, with <see cref="HeaderValue"/>, on every request while simulating.</summary>
        public required string HeaderName { get; init; }

        public required string HeaderValue { get; init; }

        /// <summary>Minutes without a simulated request after which the next one records a new start.</summary>
        public int IdleTimeoutMinutes { get; init; }

        /// <summary>True when this simulation was already running, so no new start was recorded.</summary>
        public bool Resumed { get; init; }
    }

    /// <summary>Between the wire contract of the simulation endpoints and the service's models.</summary>
    internal static class SimulationMapper
    {
        public static SimulationStartedDto ToDto(SimulationStart started) => new()
        {
            Context = ToDto(started.Context),
            HeaderName = started.HeaderName,
            HeaderValue = started.HeaderValue,
            IdleTimeoutMinutes = (int)Math.Ceiling(started.IdleTimeout.TotalMinutes),
            Resumed = started.Resumed,
        };

        public static List<SimulationCandidateDto> ToDto(IReadOnlyList<SimulationCandidate> candidates) =>
            candidates.Select(c => new SimulationCandidateDto
            {
                ObjectId = c.ObjectId,
                Email = c.Email,
                Name = c.Name,
                CanSimulate = c.CanSimulate,
                Reason = c.Reason,
            }).ToList();

        private static SimulationContextDto ToDto(SimulationContext context) => new()
        {
            IsSimulating = context.IsSimulating,
            RealUser = ToDto(context.RealUser),
            EffectiveUser = ToDto(context.EffectiveUser),
            ReadOnly = context.ReadOnly,
        };

        private static SimulationUserDto ToDto(SimulationUser user) => new() { ObjectId = user.ObjectId, Email = user.Email };
    }
}
