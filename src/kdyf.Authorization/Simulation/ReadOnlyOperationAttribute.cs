namespace kdyf.Authorization.Simulation
{
    /// <summary>
    /// Declares that a POST only reads — a search or a list whose filter goes in the body, a report — so a
    /// read-only simulation lets it through.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only POST looks at it. GET, HEAD and OPTIONS always pass a read-only simulation; PUT, PATCH and DELETE
    /// never do, marked or not. A POST without the mark is refused: forgetting it costs a 403 during a
    /// simulation, never a write made in somebody else's name.
    /// </para>
    /// <para>
    /// It is a promise about the endpoint, and nothing checks it but review: mark only what changes nothing —
    /// no row, no call to the directory, no e-mail, no queued job. A module's own DbContext refuses to save
    /// during a simulation as a second barrier; the rest has no other.
    /// </para>
    /// <para>
    /// On a controller action as an attribute; on a minimal API endpoint with
    /// <c>.WithMetadata(new ReadOnlyOperationAttribute())</c>.
    /// </para>
    /// </remarks>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public sealed class ReadOnlyOperationAttribute : Attribute
    {
    }
}
