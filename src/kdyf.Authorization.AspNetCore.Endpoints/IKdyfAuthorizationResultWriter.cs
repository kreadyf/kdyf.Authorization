using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace kdyf.Authorization.AspNetCore.Endpoints
{
    /// <summary>
    /// A rule refused the request: messages for the request as a whole, and per field.
    /// </summary>
    /// <param name="Errors">Messages that belong to no field.</param>
    /// <param name="Fields">Messages per request field, by field name.</param>
    public sealed record AuthorizationRejection(
        IReadOnlyList<string> Errors,
        IReadOnlyDictionary<string, IReadOnlyList<string>> Fields);

    /// <summary>
    /// How the library's endpoints answer. A host registers its own to keep the envelope its clients already read;
    /// without one, <see cref="DefaultKdyfAuthorizationResultWriter"/> answers plain JSON and ProblemDetails.
    /// </summary>
    /// <remarks>
    /// Only the SHAPE is the host's. What is refused, what is not found and what failed is decided by the library,
    /// and a failure never carries its own text: <see cref="Failure"/> receives the exception to log or correlate,
    /// not to show.
    /// </remarks>
    public interface IKdyfAuthorizationResultWriter
    {
        /// <summary>200 with the data.</summary>
        IResult Ok(HttpContext http, object? data);

        /// <summary>204: a deletion or an activation went through.</summary>
        IResult NoContent(HttpContext http);

        /// <summary>422: a rule refused the request.</summary>
        IResult Rejected(HttpContext http, AuthorizationRejection rejection);

        /// <summary>404: a read by id found nothing the caller may see. <paramref name="message"/> is fit to show.</summary>
        IResult NotFound(HttpContext http, string message);

        /// <summary>
        /// 500: the database or the directory failed. Already logged by the library; the answer must not include
        /// <paramref name="exception"/>'s text, which can name servers, tables or tenants.
        /// </summary>
        IResult Failure(HttpContext http, Exception exception);
    }

    /// <summary>Plain JSON for data, ProblemDetails for everything else.</summary>
    public sealed class DefaultKdyfAuthorizationResultWriter : IKdyfAuthorizationResultWriter
    {
        /// <summary>The message of every failure, whatever happened.</summary>
        public const string FailureMessage = "The request could not be completed. Try again in a moment; if it keeps failing, quote the trace id.";

        public static DefaultKdyfAuthorizationResultWriter Instance { get; } = new();

        public IResult Ok(HttpContext http, object? data) => Results.Ok(data);

        public IResult NoContent(HttpContext http) => Results.NoContent();

        public IResult Rejected(HttpContext http, AuthorizationRejection rejection) =>
            Results.ValidationProblem(
                rejection.Fields.ToDictionary(f => f.Key, f => f.Value.ToArray()),
                detail: rejection.Errors.Count > 0 ? string.Join(" ", rejection.Errors) : null,
                statusCode: StatusCodes.Status422UnprocessableEntity);

        public IResult NotFound(HttpContext http, string message) =>
            Results.Problem(detail: message, statusCode: StatusCodes.Status404NotFound);

        public IResult Failure(HttpContext http, Exception exception) =>
            Results.Problem(
                detail: FailureMessage,
                statusCode: StatusCodes.Status500InternalServerError,
                extensions: new Dictionary<string, object?> { ["traceId"] = http.TraceIdentifier });
    }

    internal static class ResultWriter
    {
        /// <summary>The host's writer, or the default one.</summary>
        public static IKdyfAuthorizationResultWriter For(HttpContext http) =>
            http.RequestServices.GetService<IKdyfAuthorizationResultWriter>() ?? DefaultKdyfAuthorizationResultWriter.Instance;
    }
}
