using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cors;
using System.Security.Claims;
using Api.Modules.UserModule;
using Api.Security;
using Api.DTOs;

using Microsoft.AspNetCore.SignalR;

namespace Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    [EnableCors("AllowAll")]
    [Authorize(Policy = "AdminOnly")]
    public class UserController : ControllerBase
    {
        private readonly IUserRepository        _repository;
        private readonly IOtpService            _otpService;
        private readonly IOtpEmailSender        _otpEmailSender;
        private readonly IPendingUserOpStore     _pendingOpStore;
        private readonly ISessionService        _sessionService;
        private readonly IRefreshTokenStore     _refreshTokenStore;
        private readonly IHubContext<DashboardHub> _hubContext;

        public UserController(
            IUserRepository        repository,
            IOtpService            otpService,
            IOtpEmailSender        otpEmailSender,
            IPendingUserOpStore     pendingOpStore,
            ISessionService        sessionService,
            IRefreshTokenStore     refreshTokenStore,
            IHubContext<DashboardHub> hubContext)
        {
            _repository        = repository;
            _otpService        = otpService;
            _otpEmailSender    = otpEmailSender;
            _pendingOpStore    = pendingOpStore;
            _sessionService    = sessionService;
            _refreshTokenStore = refreshTokenStore;
            _hubContext        = hubContext;
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private Guid GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return Guid.TryParse(claim, out Guid id) ? id : Guid.Empty;
        }

        private int GetCurrentUserRoleId()
        {
            var roleClaim = User.FindFirst("user_role_id")?.Value;
            return int.TryParse(roleClaim, out int roleId) ? roleId : 0;
        }

        private async Task<IActionResult?> SendAdminOtpAsync(Guid adminId, string purpose)
        {
            var admin = await _repository.GetByIdAsync(adminId);
            if (admin == null)
                return Unauthorized(new { message = "Admin user not found." });

            var (rateLimited, code) = await _otpService.GenerateAsync(admin.UserId, purpose);
            if (rateLimited)
                return StatusCode(429, new { code = "RATE_LIMITED", message = "Too many OTP requests. Please wait." });

            try { await _otpEmailSender.SendOtpAsync(admin.UserEmail, code!, purpose); }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEVELOPER FALLBACK] SMTP failed. Purpose: {purpose}, Email: {admin.UserEmail}, OTP: {code}");
                Console.WriteLine($"[DEVELOPER FALLBACK] {ex.Message}");
            }

            return null; // success
        }

        // ── Read ─────────────────────────────────────────────────────────────

        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetAll()
        {
            try
            {
                var users = await _repository.GetAllAsync();
                return Ok(users.Select(u => new
                {
                    userId = u.UserId, publicId = u.PublicId, u.UserName, u.UserEmail, roleId = u.AccessId, accessId = u.AccessId, u.UserRole, u.Status
                }));
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        [HttpGet("{id:guid}")]
        public async Task<IActionResult> GetById(Guid id)
        {
            try
            {
                var user = await _repository.GetByIdAsync(id);
                if (user == null) return NotFound(new { message = "User not found." });
                return Ok(new { userId = user.UserId, publicId = user.PublicId, user.UserName, user.UserEmail, roleId = user.AccessId, accessId = user.AccessId, user.UserRole, user.Status });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Update (Step 1 — request OTP) ────────────────────────────────────

        [HttpPut("{id:guid}")]
        public async Task<IActionResult> RequestUpdate(Guid id, [FromBody] UpdateUserRequest request)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var existing = await _repository.GetByIdAsync(id);
                if (existing == null) return NotFound(new { message = "User not found." });

                // Validate changes up-front
                string? newUsername      = null;
                string? newEmail         = null;
                int?    newRoleId        = null;
                string? newHashedPassword = null;

                if (!string.IsNullOrWhiteSpace(request.Username))
                {
                    var conflict = await _repository.GetByUserNameAsync(request.Username);
                    if (conflict != null && conflict.PublicId != id)
                        return Conflict(new { message = "Username is already taken." });
                    newUsername = request.Username;
                }

                if (!string.IsNullOrWhiteSpace(request.Email))
                {
                    var conflict = await _repository.GetByEmailAsync(request.Email);
                    if (conflict != null && conflict.PublicId != id)
                        return Conflict(new { message = "Email is already in use by another account." });
                    newEmail = request.Email;
                }

                if (request.RoleId.HasValue)
                {
                    if (request.RoleId < 1 || request.RoleId > 6)
                        return BadRequest(new { message = "Invalid role ID. Must be between 1 and 6." });
                    newRoleId = request.RoleId.Value;
                }

                if (!string.IsNullOrWhiteSpace(request.Password))
                    newHashedPassword = PasswordHasher.Hash(request.Password);

                // Store pending op
                _pendingOpStore.SaveUpdate(adminId, new PendingUpdateOp(
                    TargetUserId:   id,
                    Username:       newUsername,
                    Email:          newEmail,
                    RoleId:         newRoleId,
                    HashedPassword: newHashedPassword,
                    ExpiresAt:      DateTime.UtcNow.AddMinutes(15)));

                var err = await SendAdminOtpAsync(adminId, "update-user");
                if (err != null) return err;

                return Ok(new { code = "OTP_REQUIRED", message = "An OTP has been sent to your email. Verify to apply the update." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Update (Step 2 — confirm with OTP) ───────────────────────────────

        [HttpPost("confirm-update")]
        public async Task<IActionResult> ConfirmUpdate([FromBody] VerifyOtpRequest dto)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var pending = _pendingOpStore.GetUpdate(adminId);
                if (pending == null)
                    return BadRequest(new { code = "SESSION_EXPIRED", message = "Update session expired. Please start again." });

                var adminUser = await _repository.GetByIdAsync(adminId);
                if (adminUser == null) return Unauthorized(new { message = "Admin user not found." });

                var result = await _otpService.VerifyAsync(adminUser.UserId, dto.OtpCode, "update-user");
                if (result != OtpVerifyResult.Valid)
                    return OtpErrorResult(result);

                var user = await _repository.GetByIdAsync(pending.TargetUserId);
                if (user == null) return NotFound(new { message = "Target user no longer exists." });

                if (pending.Username       != null) user.UserName  = pending.Username;
                if (pending.Email          != null) user.UserEmail  = pending.Email;
                if (pending.RoleId         != null) user.AccessId  = pending.RoleId.Value;
                if (pending.HashedPassword != null) user.UserPass  = pending.HashedPassword;

                await _repository.UpdateAsync(user);
                _pendingOpStore.RemoveUpdate(adminId);

                // Force logout affected target user session & revoke tokens
                _sessionService.MarkUserLoggedOut(user.UserId);
                _refreshTokenStore.RevokeRefreshToken(user.PublicId);
                try { await _hubContext.Clients.Group($"User_{user.PublicId}").SendAsync("ForceLogout", new { reason = "ACCOUNT_UPDATED" }); } catch { }

                return Ok(new { message = "User updated successfully." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Delete (Step 1 — request OTP) ────────────────────────────────────

        [HttpDelete("{id:guid}")]
        public async Task<IActionResult> RequestDelete(Guid id)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var existing = await _repository.GetByIdAsync(id);
                if (existing == null) return NotFound(new { message = "User not found." });

                if (id == adminId)
                    return BadRequest(new { message = "You cannot delete your own account." });

                _pendingOpStore.SaveDelete(adminId, new PendingDeleteOp(
                    TargetUserId: id,
                    ExpiresAt:    DateTime.UtcNow.AddMinutes(15)));

                var err = await SendAdminOtpAsync(adminId, "delete-user");
                if (err != null) return err;

                return Ok(new { code = "OTP_REQUIRED", message = "An OTP has been sent to your email. Verify to confirm deletion." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Delete (Step 2 — confirm with OTP) ───────────────────────────────

        [HttpPost("confirm-delete")]
        public async Task<IActionResult> ConfirmDelete([FromBody] VerifyOtpRequest dto)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var pending = _pendingOpStore.GetDelete(adminId);
                if (pending == null)
                    return BadRequest(new { code = "SESSION_EXPIRED", message = "Delete session expired. Please start again." });

                var adminUser = await _repository.GetByIdAsync(adminId);
                if (adminUser == null) return Unauthorized(new { message = "Admin user not found." });

                var result = await _otpService.VerifyAsync(adminUser.UserId, dto.OtpCode, "delete-user");
                if (result != OtpVerifyResult.Valid)
                    return OtpErrorResult(result);

                if (pending.TargetUserId == adminId)
                    return BadRequest(new { message = "You cannot delete your own account." });

                var existing = await _repository.GetByIdAsync(pending.TargetUserId);
                if (existing == null) return NotFound(new { message = "Target user no longer exists." });

                await _repository.DeleteAsync(pending.TargetUserId);
                _pendingOpStore.RemoveDelete(adminId);

                // Force logout deleted user session & revoke tokens
                _sessionService.MarkUserLoggedOut(existing.UserId);
                _refreshTokenStore.RevokeRefreshToken(existing.PublicId);
                try { await _hubContext.Clients.Group($"User_{existing.PublicId}").SendAsync("ForceLogout", new { reason = "ACCOUNT_DELETED" }); } catch { }

                return Ok(new { message = "User deleted successfully." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Restoration (Get deleted users) ───────────────────────────

        [HttpGet("deleted")]
        public async Task<ActionResult<IEnumerable<User>>> GetDeleted()
        {
            try
            {
                var deletedUsers = await _repository.GetDeletedAsync();
                return Ok(deletedUsers.Select(u => new
                {
                    userId = u.UserId,
                    publicId = u.PublicId,
                    u.UserName,
                    u.UserEmail,
                    roleId = u.AccessId,
                    accessId = u.AccessId,
                    u.UserRole,
                    u.Status,
                    u.IsDeleted,
                    u.DeletedAt
                }));
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Restoration (Step 1 — request OTP) ───────────────────────

        [HttpPost("{id:guid}/restore")]
        public async Task<IActionResult> RequestRestore(Guid id)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var existing = await _repository.GetByIdIncludingDeletedAsync(id);
                if (existing == null) return NotFound(new { message = "User account not found." });

                if (!existing.IsDeleted)
                    return BadRequest(new { message = "User account is not deleted." });

                _pendingOpStore.SaveRestore(adminId, new PendingRestoreOp(
                    TargetUserId: id,
                    ExpiresAt:    DateTime.UtcNow.AddMinutes(15)));

                var err = await SendAdminOtpAsync(adminId, "restore-user");
                if (err != null) return err;

                return Ok(new { code = "OTP_REQUIRED", message = "An OTP has been sent to your email. Verify to confirm account restoration." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Restoration (Step 2 — confirm with OTP) ───────────────────

        [HttpPost("confirm-restore")]
        public async Task<IActionResult> ConfirmRestore([FromBody] VerifyOtpRequest dto)
        {
            try
            {
                var adminId = GetCurrentUserId();
                if (adminId == Guid.Empty) return Unauthorized(new { message = "Not authenticated." });

                var pending = _pendingOpStore.GetRestore(adminId);
                if (pending == null)
                    return BadRequest(new { code = "SESSION_EXPIRED", message = "Restoration session expired. Please start again." });

                var adminUser = await _repository.GetByIdAsync(adminId);
                if (adminUser == null) return Unauthorized(new { message = "Admin user not found." });

                var result = await _otpService.VerifyAsync(adminUser.UserId, dto.OtpCode, "restore-user");
                if (result != OtpVerifyResult.Valid)
                    return OtpErrorResult(result);

                var existing = await _repository.GetByIdIncludingDeletedAsync(pending.TargetUserId);
                if (existing == null) return NotFound(new { message = "Target user account no longer exists." });

                await _repository.RestoreAsync(pending.TargetUserId);
                _pendingOpStore.RemoveRestore(adminId);

                return Ok(new { message = "User account restored successfully." });
            }
            catch (Exception ex) { return StatusCode(500, new { message = ex.Message }); }
        }

        // ── Utility ──────────────────────────────────────────────────────────

        private IActionResult OtpErrorResult(OtpVerifyResult result) => result switch
        {
            OtpVerifyResult.Expired            => Unauthorized(new { code = "OTP_EXPIRED",  message = "OTP has expired. Please start again." }),
            OtpVerifyResult.MaxAttemptsReached => Unauthorized(new { code = "OTP_LOCKED",   message = "Too many failed attempts." }),
            OtpVerifyResult.RateLimited        => StatusCode(429, new { code = "RATE_LIMITED", message = "Too many attempts. Please wait." }),
            _                                  => Unauthorized(new { code = "OTP_INVALID",  message = "Invalid OTP code." })
        };
    }
}