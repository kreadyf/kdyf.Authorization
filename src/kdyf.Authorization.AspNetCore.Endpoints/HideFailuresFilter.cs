using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace kdyf.Authorization.AspNetCore.Endpoints
{
    /// <summary>
    /// On every endpoint of the library: a failure of the database, the directory or anything else is logged whole
    /// and answered through <see cref="IKdyfAuthorizationResultWriter.Failure"/>, never with its own text — a
    /// connection string, a server or a tenant name must not reach a client.
    /// </summary>
    /// <remarks>
    /// Refusals and "not found" are not exceptions here: the endpoints answer them. A cancelled request is let
    /// through, to end as the framework ends it.
    /// </remarks>
    internal sealed class HideFailuresFilter : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            try
            {
                return await next(context);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                var http = context.HttpContext;
                http.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("kdyf.Authorization.Endpoints")
                    .LogError(exception, "{Method} {Path} failed ({TraceId}).", http.Request.Method, http.Request.Path, http.TraceIdentifier);

                return ResultWriter.For(http).Failure(http, exception);
            }
        }
    }
}
