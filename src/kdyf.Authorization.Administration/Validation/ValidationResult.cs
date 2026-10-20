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
        /// <summary>
        /// Creates the envelope. With <paramref name="isValid"/> null the result starts INVALID
        /// (<see cref="Validation.IsValid"/> defaults to false): say <c>true</c> for a success.
        /// </summary>
        public ValidationResult(bool? isValid = null)
        {
            Validation = new MultipleFieldValidation();

            if (isValid != null)
                Validation.IsValid = isValid.Value;
        }

        /// <summary>Whether the operation was accepted, with the general and per-field errors when it was not.</summary>
        public MultipleFieldValidation Validation { get; set; }
    }

    /// <inheritdoc cref="ValidationResult"/>
    /// <typeparam name="T">Payload returned when the operation is valid.</typeparam>
    public class ValidationResult<T> : ValidationResult
    {
        // 'default!' and not a nullable type: the serialized shape has to stay the same, and in an
        // invalid result this field is simply not read.
        /// <summary>The payload. Only meaningful when <see cref="ValidationResult.Validation"/> is valid.</summary>
        public T Data { get; set; } = default!;
    }

    /// <summary>Result of a validation: whether it is valid, and its messages.</summary>
    public class Validation
    {
        /// <summary>Creates an invalid validation with no errors yet.</summary>
        public Validation()
        {
            IsValid = false;
            Errors = new List<string>();
        }

        /// <summary>Whether it is valid. False by default; adding any error sets it to false.</summary>
        public bool IsValid { get; set; }

        /// <summary>General messages, not tied to a field.</summary>
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
        /// <summary>Creates an invalid validation with no errors and no fields yet.</summary>
        public MultipleFieldValidation() : base()
        {
            Fields = new Dictionary<string, Validation>();
        }

        /// <summary>Per-field validations, keyed by field name. Read <c>Fields[field].Errors</c>.</summary>
        public Dictionary<string, Validation> Fields { get; set; }

        /// <summary>Adds an error to <paramref name="fieldName"/>; the field and the whole result become invalid.</summary>
        public void AddFieldError(string fieldName, string message)
        {
            AddFieldErrors(fieldName, new[] { message });
        }

        /// <summary>Adds errors to <paramref name="fieldName"/>; the field and the whole result become invalid.</summary>
        public void AddFieldErrors(string fieldName, string[] messages)
        {
            if (!Fields.ContainsKey(fieldName))
                Fields.Add(fieldName, new Validation());

            Fields[fieldName].Errors.AddRange(messages);
            Fields[fieldName].IsValid = false;

            IsValid = false;
        }

        /// <summary>Adds a general error; the result becomes invalid.</summary>
        public void AddError(string message)
        {
            Errors.Add(message);
            IsValid = false;
        }
    }
}
