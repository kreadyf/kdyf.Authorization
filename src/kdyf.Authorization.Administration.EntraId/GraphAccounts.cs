using kdyf.Authorization.Administration.Abstractions;
using kdyf.Authorization.EntraId;

namespace kdyf.Authorization.Administration.EntraId
{
    /// <summary>
    /// People as the administration sees them — whatever decides who has access: read from Microsoft Graph with whether
    /// their account is enabled, and Graph's failures in this library's vocabulary.
    /// </summary>
    internal sealed class GraphAccounts
    {
        public const string UserFields = "id,displayName,mail,otherMails,userPrincipalName,userType,accountEnabled";

        /// <summary>How many ids one <c>id in (...)</c> filter may carry.</summary>
        private const int IdsPerQuery = 15;

        private readonly GraphClient _graph;

        public GraphAccounts(GraphClient graph) => _graph = graph;

        /// <summary>Anybody in the directory, with or without access. Null when unknown or not an object id.</summary>
        public Task<DirectoryAccount?> GetUserAsync(string objectId, CancellationToken cancellationToken) => Call(async () =>
        {
            if (!GraphClient.IsObjectId(objectId))
                return null;

            var user = await _graph.GetOrNullAsync<GraphDirectoryService.GraphUser>(
                $"users/{objectId}?$select={UserFields}", "reading the user", cancellationToken);

            return user is null ? null : (DirectoryAccount?)ToAccount(user);
        });

        /// <summary>The ones Graph knows, in batches; ids that are not object ids are left out.</summary>
        public Task<IReadOnlyList<DirectoryAccount>> GetUsersAsync(IReadOnlyCollection<string> objectIds, CancellationToken cancellationToken) => Call(async () =>
        {
            var found = new List<DirectoryAccount>();
            foreach (var chunk in objectIds.Where(GraphClient.IsObjectId).Distinct(StringComparer.OrdinalIgnoreCase).Chunk(IdsPerQuery))
            {
                var ids = string.Join(",", chunk.Select(id => $"'{id}'"));
                var page = await _graph.GetAllAsync<GraphDirectoryService.GraphUser>(
                    $"users?$filter=id in ({ids})&$select={UserFields}", "reading users", cancellationToken);

                found.AddRange(page.Where(u => u.Id is not null).Select(ToAccount));
            }

            IReadOnlyList<DirectoryAccount> result = found;
            return result;
        });

        public static DirectoryAccount ToAccount(GraphDirectoryService.GraphUser user) =>
            // Null only when Graph was not allowed to read it: counted as disabled, never as enabled.
            new(GraphDirectoryService.ToDirectoryUser(user), user.AccountEnabled == true);

        /// <summary>Graph's failures, in this library's vocabulary.</summary>
        public static async Task<T> Call<T>(Func<Task<T>> call)
        {
            try
            {
                return await call();
            }
            catch (GraphException ex)
            {
                throw new DirectoryException(ex.Message, ex);
            }
        }

        /// <inheritdoc cref="Call{T}"/>
        public static async Task Call(Func<Task> call)
        {
            try
            {
                await call();
            }
            catch (GraphException ex)
            {
                throw new DirectoryException(ex.Message, ex);
            }
        }
    }
}
