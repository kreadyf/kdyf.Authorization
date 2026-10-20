using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.Abstractions;

namespace kdyf.Authorization.Administration.Test;

/// <summary>
/// An in-memory Entra tenant: people, whether their account is enabled, and who is in the access group.
/// Everything the libraries read or write in Entra goes through it, so a test can assert what was really
/// changed — and make it fail on cue.
/// </summary>
internal sealed class FakeEntra : IMembershipSource, IAccessDirectory, IDirectoryService
{
    private readonly Dictionary<string, Person> _people = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every write that reached "Graph", in order: "add oid" / "remove oid" / "invite email".</summary>
    internal List<string> Writes { get; } = new();

    /// <summary>Throw on the Nth write (1-based), after the previous ones succeeded.</summary>
    internal int? FailOnWrite { get; set; }

    /// <summary>Throw on every read.</summary>
    internal bool ReadsFail { get; set; }

    /// <summary>A person in the tenant; <paramref name="member"/> puts them directly in the access group.</summary>
    internal FakeEntra Add(string objectId, string email, bool member = true)
    {
        _people[objectId] = new Person(objectId, email) { Member = member };
        return this;
    }

    internal FakeEntra Disable(string objectId)
    {
        _people[objectId].Enabled = false;
        return this;
    }

    /// <summary>Also a member through a nested group: removing the direct membership leaves them in.</summary>
    internal FakeEntra NestIn(string objectId)
    {
        _people[objectId].Nested = true;
        return this;
    }

    /// <summary>Takes them out of the group "in the Entra portal", behind the application's back.</summary>
    internal FakeEntra LeaveGroup(string objectId)
    {
        _people[objectId].Member = false;
        return this;
    }

    /// <summary>Deletes the account "in the Entra portal".</summary>
    internal FakeEntra Delete(string objectId)
    {
        _people.Remove(objectId);
        return this;
    }

    internal bool IsMember(string objectId) => _people.TryGetValue(objectId, out var p) && p.IsMember;

    // ── IMembershipSource ────────────────────────────────────────────────────

    public Task<Membership?> GetMembershipAsync(string subjectId, CancellationToken cancellationToken = default)
    {
        Read();
        return Task.FromResult(_people.TryGetValue(subjectId, out var p) ? new Membership(p.Enabled, p.IsMember) : null);
    }

    Task<DirectoryIdentity?> IMembershipSource.FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        Read();
        var p = _people.Values.FirstOrDefault(x => string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(p is null ? null : new DirectoryIdentity(p.ObjectId, p.Email, p.Email));
    }

    // ── IAccessDirectory ────────────────────────────────────────────────

    public Task<IReadOnlyList<DirectoryAccount>> ListWithAccessAsync(CancellationToken cancellationToken = default)
    {
        Read();
        IReadOnlyList<DirectoryAccount> list = _people.Values.Where(p => p.IsMember).Select(ToAccount).ToList();
        return Task.FromResult(list);
    }

    public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken = default)
    {
        Read();
        return Task.FromResult(_people.TryGetValue(objectId, out var p) ? ToAccount(p) : null);
    }

    public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken = default)
    {
        Read();
        IReadOnlyList<DirectoryAccount> list = objectIds
            .Where(_people.ContainsKey)
            .Select(id => ToAccount(_people[id]))
            .ToList();
        return Task.FromResult(list);
    }

    /// <summary>
    /// Runs once, right after the membership of <see cref="MeanwhileFor"/> is asked: what another administrator did in the
    /// meantime.
    /// </summary>
    internal Action? Meanwhile { get; set; }

    /// <summary>Whose membership check triggers <see cref="Meanwhile"/>.</summary>
    internal string? MeanwhileFor { get; set; }

    public Task<bool> HasAccessAsync(string objectId, CancellationToken cancellationToken = default)
    {
        Read();
        var member = IsMember(objectId);
        if (Meanwhile is { } meanwhile && string.Equals(objectId, MeanwhileFor, StringComparison.OrdinalIgnoreCase))
        {
            Meanwhile = null;
            meanwhile();
        }
        return Task.FromResult(member);
    }

    public Task GrantAsync(string objectId, CancellationToken cancellationToken = default)
    {
        Write($"add {objectId}");
        _people[objectId].Member = true;
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string objectId, CancellationToken cancellationToken = default)
    {
        Write($"remove {objectId}");
        if (_people.TryGetValue(objectId, out var p))
            p.Member = false;
        return Task.CompletedTask;
    }

    // ── IDirectoryService ────────────────────────────────────────────────────

    public Task<IReadOnlyList<DirectoryUser>> SearchAsync(string search, CancellationToken cancellationToken = default)
    {
        Read();
        IReadOnlyList<DirectoryUser> found = _people.Values
            .Where(p => p.Email.Contains(search, StringComparison.OrdinalIgnoreCase))
            .Select(ToDirectoryUser)
            .ToList();
        return Task.FromResult(found);
    }

    Task<DirectoryUser?> IDirectoryService.FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        Read();
        var p = _people.Values.FirstOrDefault(x => string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(p is null ? null : ToDirectoryUser(p));
    }

    public Task<DirectoryInvitation> InviteAsync(string email, string? displayName, CancellationToken cancellationToken = default)
    {
        Write($"invite {email}");
        var objectId = Guid.NewGuid().ToString();
        _people[objectId] = new Person(objectId, email) { Guest = true, Member = false };
        return Task.FromResult(new DirectoryInvitation(ToDirectoryUser(_people[objectId]), "https://redeem.test/x", EmailSent: true));
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private static DirectoryAccount ToAccount(Person p) => new(ToDirectoryUser(p), p.Enabled);

    private static DirectoryUser ToDirectoryUser(Person p) => new(p.ObjectId, p.Email, p.Email, p.Email, p.Guest);

    private void Read()
    {
        if (ReadsFail)
            throw new DirectoryException("Graph is unreachable.");
    }

    private void Write(string what)
    {
        if (FailOnWrite == Writes.Count + 1)
            throw new DirectoryException($"Graph refused: {what}.");
        Writes.Add(what);
    }

    private sealed class Person
    {
        internal Person(string objectId, string email)
        {
            ObjectId = objectId;
            Email = email;
        }

        internal string ObjectId { get; }
        internal string Email { get; }
        internal bool Enabled { get; set; } = true;
        internal bool Guest { get; set; }
        internal bool Member { get; set; }
        internal bool Nested { get; set; }
        internal bool IsMember => Member || Nested;
    }
}
