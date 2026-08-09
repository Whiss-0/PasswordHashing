using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Api.Security
{
    // ─── Interface ────────────────────────────────────────────────────────────

    public interface IOtpEmailSender
    {
        Task SendOtpAsync(string toEmail, string otpCode, string purpose,
                          CancellationToken ct = default);
    }


    public class SmtpOtpEmailSender : IOtpEmailSender
    {
        private readonly IConfiguration             _config;
        private readonly ILogger<SmtpOtpEmailSender> _logger;

        public SmtpOtpEmailSender(IConfiguration config, ILogger<SmtpOtpEmailSender> logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task SendOtpAsync(string toEmail, string otpCode, string purpose,
                                       CancellationToken ct = default)
        {
            var host     = _config["Smtp:Host"]     ?? throw new InvalidOperationException("Smtp:Host is not configured.");
            var portStr  = _config["Smtp:Port"]     ?? "587";
            var user     = _config["Smtp:Username"] ?? throw new InvalidOperationException("Smtp:Username is not configured.");
            var pass     = _config["Smtp:Password"] ?? throw new InvalidOperationException("Smtp:Password is not configured.");
            var fromName = _config["Smtp:FromName"] ?? "Student Portal";
            var from     = _config["Smtp:From"]     ?? user;

            var subject = purpose switch
            {
                "login"        => "Your Login Verification Code",
                "reset"        => "Your Password Reset Code",
                "change-email" => "Verify Your New Email Address",
                "register"     => "Verify Your Email Address",
                _              => "Your Verification Code"
            };

            // ── Build MimeMessage ────────────────────────────────────────────
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, from));
            message.To.Add(new MailboxAddress(toEmail, toEmail));
            message.Subject = subject;
            message.Body    = new BodyBuilder
            {
                HtmlBody = BuildEmailBody(otpCode, purpose, fromName)
            }.ToMessageBody();

            // ── Send via MailKit ─────────────────────────────────────────────
            // StartTls on port 587 is the standard for Gmail / most providers.
            // MailKit handles the STARTTLS upgrade automatically.
            try
            {
                using var client = new SmtpClient();
                await client.ConnectAsync(host, int.Parse(portStr),
                                          SecureSocketOptions.StartTls, ct);
                await client.AuthenticateAsync(user, pass, ct);
                await client.SendAsync(message, ct);
                await client.DisconnectAsync(quit: true, ct);

                _logger.LogInformation("OTP email sent to {Email} [{Purpose}].", toEmail, purpose);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send OTP email to {Email}.", toEmail);
                throw;
            }
        }

        // ─── Email HTML template ─────────────────────────────────────────────

        private static string BuildEmailBody(string code, string purpose, string appName) => $"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="margin:0;padding:0;background:#0f0f1a;font-family:'Segoe UI',Arial,sans-serif;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f0f1a;padding:40px 0;">
                <tr><td align="center">
                  <table width="480" cellpadding="0" cellspacing="0"
                         style="background:#1a1a2e;border-radius:16px;overflow:hidden;
                                border:1px solid rgba(99,102,241,0.3);">

                    <!-- Header -->
                    <tr><td style="background:linear-gradient(135deg,#6366f1,#8b5cf6);
                                   padding:32px;text-align:center;">
                      <h1 style="margin:0;color:#fff;font-size:22px;font-weight:700;
                                 letter-spacing:1px;">{appName}</h1>
                    </td></tr>

                    <!-- Body -->
                    <tr><td style="padding:36px 40px;">
                      <p style="margin:0 0 8px;color:#a5b4fc;font-size:13px;
                                text-transform:uppercase;letter-spacing:1px;">
                        Verification Code
                      </p>
                      <p style="margin:0 0 28px;color:#e2e8f0;font-size:15px;line-height:1.6;">
                        {GetPurposeMessage(purpose)}
                      </p>

                      <!-- OTP Box -->
                      <div style="background:#0f0f1a;border:2px solid #6366f1;border-radius:12px;
                                  text-align:center;padding:24px;margin-bottom:28px;">
                        <span style="font-size:42px;font-weight:800;
                                     letter-spacing:12px;color:#a5b4fc;
                                     font-family:'Courier New',monospace;">{code}</span>
                      </div>

                      <p style="margin:0 0 8px;color:#94a3b8;font-size:13px;text-align:center;">
                        ⏱ This code expires in <strong style="color:#e2e8f0;">10 minutes</strong>.
                      </p>
                      <p style="margin:0;color:#64748b;font-size:12px;text-align:center;">
                        If you didn't request this, you can safely ignore this email.
                      </p>
                    </td></tr>

                    <!-- Footer -->
                    <tr><td style="border-top:1px solid rgba(99,102,241,0.2);
                                   padding:20px 40px;text-align:center;">
                      <p style="margin:0;color:#475569;font-size:12px;">
                        © {DateTime.Now.Year} {appName}. Do not reply to this email.
                      </p>
                    </td></tr>

                  </table>
                </td></tr>
              </table>
            </body>
            </html>
            """;

        private static string GetPurposeMessage(string purpose) => purpose switch
        {
            "login"        => "Use the code below to complete your login. Do not share it with anyone.",
            "reset"        => "Use the code below to reset your password. Do not share it with anyone.",
            "change-email" => "Use the code below to verify your new email address.",
            "register"     => "Welcome! Use the code below to verify your email and activate your account.",
            _              => "Use the code below to complete your request."
        };
    }

    // ─── Development Fallback Sender ──────────────────────────────────────────
    // Registered instead of SmtpOtpEmailSender when ASPNETCORE_ENVIRONMENT=Development.
    // Tries SMTP first; on failure it prints the OTP to the console so you can
    // test the full OTP flow without a real SMTP / App Password configuration.

    public class DevOtpEmailSender : IOtpEmailSender
    {
        private readonly SmtpOtpEmailSender              _smtp;
        private readonly ILogger<DevOtpEmailSender>      _logger;

        public DevOtpEmailSender(
            SmtpOtpEmailSender         smtp,
            ILogger<DevOtpEmailSender> logger)
        {
            _smtp   = smtp;
            _logger = logger;
        }

        public async Task SendOtpAsync(string toEmail, string otpCode, string purpose,
                                       CancellationToken ct = default)
        {
            try
            {
                await _smtp.SendOtpAsync(toEmail, otpCode, purpose, ct);
            }
            catch (Exception ex)
            {
                // SMTP failed in dev — log the code so testing can continue
                _logger.LogWarning(
                    "⚡ [DEV] SMTP delivery failed ({Reason}). " +
                    "OTP for {Email} [{Purpose}]: {Code}  — use this code to complete the flow.",
                    ex.Message, toEmail, purpose, otpCode);

                // Do NOT rethrow — the request proceeds as if email was sent
            }
        }
    }
}
