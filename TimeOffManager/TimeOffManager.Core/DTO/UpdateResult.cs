namespace TimeOffManager.Core.DTO
{
    public record UpdateResult<T>
    {
        public string Message { get; set; }
        public bool Success { get; set; }

        public T UpdatedResult { get; set; }

        public UpdateResult(string message, bool success, T res)
        {
            Message = message;
            Success = success;
            UpdatedResult = res;
        }

        public UpdateResult(string message, bool success)
        {
            Message = message;
            Success = success;
        }

        public static UpdateResult<T> Ok(T res) => new UpdateResult<T>("", true, res);
        public static UpdateResult<T> Error(string message) => new UpdateResult<T>(message, false); 
    }
}
