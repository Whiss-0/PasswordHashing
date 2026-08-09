using Google.Apis.Auth;

namespace Api.Security
{
    /// <summary>
    /// Validates Google ID tokens sent from the frontend (Google Sign-In SDK).
    /// </summary>
    public interface IGoogleAuthService
    {
        /// <summary>
        /// Validates the given Google ID token and returns its payload on success,
        /// or <c>null</c> if the token is invalid or expired.
        /// </summary>
        Task<GoogleJsonWebSignature.Payload?> ValidateTokenAsync(string idToken);
    }

    /// <inheritdoc />
    public sealed class GoogleAuthService : IGoogleAuthService
    {
        private readonly string _clientId;

        public GoogleAuthService(IConfiguration configuration)
        {
            _clientId = configuration["Google:ClientId"]
                ?? throw new InvalidOperationException(
                    "Google:ClientId is not configured. " +
                    "Add it to appsettings.json or User Secrets.");
        }

        /// <inheritdoc />
        public async Task<GoogleJsonWebSignature.Payload?> ValidateTokenAsync(string idToken)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = [_clientId]
                };

                // Validates signature, expiry, issuer, and audience automatically.
                var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, settings);
                return payload;
            }
            catch (InvalidJwtException ex)
            {
                Console.WriteLine($"[GOOGLE AUTH] Invalid ID token: {ex.Message}");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[GOOGLE AUTH] Unexpected error validating token: {ex.Message}");
                return null;
            }
        }
    }
}
