namespace kdyf.Authorization.Administration.Validation
{
    /// <summary>The two ways a service answers: the data, or a field error.</summary>
    internal static class Outcome
    {
        public static ValidationResult<T> Ok<T>(T data)
        {
            var result = new ValidationResult<T> { Data = data };
            result.Validation.IsValid = true;
            return result;
        }

        public static ValidationResult<T> Error<T>(string field, string message)
        {
            var result = new ValidationResult<T>();
            result.Validation.AddFieldError(field, message);
            result.Validation.IsValid = false;
            return result;
        }
    }
}
