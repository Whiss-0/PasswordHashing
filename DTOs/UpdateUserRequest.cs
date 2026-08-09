namespace Api.DTOs
{
    public class UpdateUserRequest
    {
        public string? Username { get; set; }
        public string? Email    { get; set; }
        public int?    RoleId   { get; set; }
        public string? Password { get; set; }
    }
}