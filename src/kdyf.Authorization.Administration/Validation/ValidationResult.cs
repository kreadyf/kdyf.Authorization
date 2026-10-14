using System.Collections.Generic;

namespace kdyf.Authorization.Administration.Validation
{
    /// <summary>
    /// API response envelope: the payload together with the result of its validation.
    /// </summary>
    /// <remarks>
    /// The convention is that a rejection travels with **HTTP 200** and <c>Validation.IsValid = false</c>,
    /// not with an error code: the client has to look at the validation node, not the status.
    ///
    /// It lives apart —and not inside the library that returns it— because it belongs to no
    /// domain: it is the response contract the administration services return.
    ///
    /// The SERIALIZED SHAPE is the contract: the names and casing of <c>Validation</c>,
    /// <c>IsValid</c>, <c>Errors</c>, <c>Fields</c> and <c>Data</c> are not to be touched.
    /// </remarks>
    public class ValidationResult
    {
        public ValidationResult(bool? isValid = null)
        {
            Validation = new MultipleFieldValidation();

            if (isValid != null)
                Validation.IsValid = isValid.Value;
        }

        public MultipleFieldValidation Validation { get; set; }
    }

    /// <inheritdoc cref="ValidationResult"/>
    /// <typeparam name="T">Payload returned when the operation is valid.</typeparam>
    public class ValidationResult<T> : ValidationResult
    {
        // 'default!' and not a nullable type: the serialized shape has to stay the same, and in an
        // invalid result this field is simply not read.
        public T Data { get; set; } = default!;
    }

    /// <summary>Result of a validation: whether it is valid, and its messages.</summary>
    public class Validation
    {
        public Validation()
        {
            IsValid = false;
            Errors = new List<string>();
        }

        public bool IsValid { get; set; }

        public List<string> Errors { get; set; }
    }

    /// <summary>
    /// Validation with per-field errors, in addition to the general ones.
    /// </summary>
    /// <remarks>
    /// <c>Fields</c> is a dictionary of full <see cref="Validation"/> objects, not of text lists:
    /// you have to read <c>Fields[field].Errors</c>. Treating it as <c>string[]</c> silently discards
    /// all the per-field errors, which are exactly the ones drawn next to each input.
    /// </remarks>
    public class MultipleFieldValidation : Validation
    {
        public MultipleFieldValidation() : base()
        {
            Fields = new Dictionary<string, Validation>();
        }

        public Dictionary<string, Validation> Fields { get; set; }

        public void AddFieldError(string fieldName, string message)
        {
            AddFieldErrors(fieldName, new[] { message });
        }

        public void AddFieldErrors(string fieldName, string[] messages)
        {
            if (!Fields.ContainsKey(fieldName))
                Fields.Add(fieldName, new Validation());

            Fields[fieldName].Errors.AddRange(messages);
            Fields[fieldName].IsValid = false;

            IsValid = false;
        }

        public void AddError(string message)
        {
            Errors.Add(message);
            IsValid = false;
        }
    }
}
