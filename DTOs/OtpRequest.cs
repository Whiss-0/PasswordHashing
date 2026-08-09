namespace Api.DTOs
{
    public class VerifyOtpRequest
    {
        public string OtpCode     { get; set; } = string.Empty;
        public bool   TrustDevice { get; set; } = true;
    }

    public class UnifiedOtpVerifyRequest
    {
        public string? Email       { get; set; }
        public string  OtpCode     { get; set; } = string.Empty;
        public string  Purpose     { get; set; } = string.Empty; 
        public string? NewPassword { get; set; } 
    }

    public class VerifyLoginOtpRequest
    {
        public string? Email   { get; set; }
        public string  OtpCode { get; set; } = string.Empty;
    }


    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class RequestChangeEmailRequest
    {
        public string NewEmail { get; set; } = string.Empty;
    }

    public class VerifyChangeEmailRequest
    {
        public string NewEmail { get; set; } = string.Empty;
        public string OtpCode  { get; set; } = string.Empty;
    }

    public class ResetPasswordRequest
    {
        public string OtpCode      { get; set; } = string.Empty;
        public string NewPassword  { get; set; } = string.Empty;
    }

    public class ResendOtpRequest
    {
        public string Context { get; set; } = string.Empty;
    }
}
