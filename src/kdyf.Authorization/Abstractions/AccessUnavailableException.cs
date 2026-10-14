namespace kdyf.Authorization.Abstractions
{
    /// <summary>
    /// Who may do what could not be read — the database or the directory failed. The message is fixed and fit to be
    /// shown to anybody; what really happened is the <see cref="Exception.InnerException"/>, for the log only.
    /// </summary>
    /// <remarks>
    /// Thrown where the library reaches its stores on a request: resolving a person's permissions and resolving the
    /// person a simulation borrows. The original exception can carry a server name, a database login or a fragment
    /// of a connection string, and a host that shows an exception's message to the client would show it.
    /// </remarks>
    public sealed class AccessUnavailableException : Exception
    {
        /// <summary>What the client reads.</summary>
        public const string Reason = "The access service is not available right now. Try again in a moment.";

        public AccessUnavailableException(Exception inner) : base(Reason, inner) { }

        /// <summary>
        /// The failure to wrap, or null when it must travel as it is: a cancellation, or one already wrapped.
        /// </summary>
        public static Exception? Wrap(Exception exception) =>
            exception is OperationCanceledException or AccessUnavailableException ? null : new AccessUnavailableException(exception);
    }
}
