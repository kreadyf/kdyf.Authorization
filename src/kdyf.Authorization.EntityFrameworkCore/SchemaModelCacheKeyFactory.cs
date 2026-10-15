using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace kdyf.Authorization.EntityFrameworkCore
{
    /// <summary>A context whose tables live in a schema chosen at runtime.</summary>
    public interface ISchemaQualifiedContext
    {
        /// <summary>The schema of the context's tables.</summary>
        string Schema { get; }
    }

    /// <summary>
    /// Caches a model per context type AND schema. EF caches one model per context type; without the schema in the key,
    /// the second context of a type built with another schema in the same process (two databases, or the old and the new
    /// schema side by side during a migration) would silently get the first one's tables.
    /// </summary>
    public sealed class SchemaModelCacheKeyFactory : IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) =>
            context is ISchemaQualifiedContext qualified
                ? (context.GetType(), qualified.Schema, designTime)
                : (context.GetType(), designTime);
    }
}
