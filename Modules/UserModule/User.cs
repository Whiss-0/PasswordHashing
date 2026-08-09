using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Api.Modules.UserModule
{
    public sealed class User : IEquatable<User>
    {
        public const int UserNameMaxLen = 50;
        public const int StatusMaxLen   = 30;

        private int?      _userId;     // internal DB IDENTITY key (user_id)
        private Guid?     _guid;       // external GUID column (guid)
        private int       _accessId;   // FK to Access_Roles(access_id)
        private string?   _userName;   // username column
        private string?   _userPass;   // password_hash column
        private string?   _userEmail;  // email column
        private bool      _emailVerified; // email_verified column
        private string?   _userRole;   // joined from Access_Roles(role_name)
        private string?   _status;     // status column
        private bool      _isDeleted;  // is_deleted column
        private DateTime? _deletedAt;  // deleted_at column
        private DateTime  _createdAt;  // created_at column
        private DateTime? _updatedAt;  // updated_at column

        public User() { }

        /// <summary>
        /// Internal auto-increment primary key (user_id).
        /// </summary>
        public int UserId
        {
            get => _userId ?? 0;
            set => _userId = value;
        }

        /// <summary>
        /// Public GUID identifier (guid column in users table).
        /// </summary>
        public Guid PublicId
        {
            get => _guid ?? Guid.Empty;
            set => _guid = value;
        }

        public int AccessId
        {
            get => _accessId;
            set => _accessId = value;
        }

        /// <summary>
        /// Backward-compatible alias for AccessId (corresponds to Access_Roles.access_id).
        /// </summary>
        public int RoleId
        {
            get => AccessId;
            set => AccessId = value;
        }

        [StringLength(UserNameMaxLen)]
        public string UserName
        {
            get => _userName ?? string.Empty;
            set
            {
                var s = NormalizeSpaces(value);
                if (s.Length > UserNameMaxLen)
                    throw new ArgumentException($"UserName exceeds {UserNameMaxLen} characters.");
                _userName = s;
            }
        }

        public string UserPass
        {
            get => _userPass ?? string.Empty;
            set => _userPass = value ?? string.Empty;
        }

        [StringLength(150)]
        public string UserEmail
        {
            get => _userEmail ?? string.Empty;
            set => _userEmail = value ?? string.Empty;
        }

        public bool EmailVerified
        {
            get => _emailVerified;
            set => _emailVerified = value;
        }

        /// <summary>
        /// Joined field — populated from Access_Roles.role_name via AccessId.
        /// </summary>
        public string UserRole
        {
            get => _userRole ?? string.Empty;
            set => _userRole = value ?? string.Empty;
        }

        [StringLength(StatusMaxLen)]
        public string Status
        {
            get => _status ?? string.Empty;
            set => _status = value ?? string.Empty;
        }

        public bool IsDeleted
        {
            get => _isDeleted;
            set => _isDeleted = value;
        }

        public DateTime? DeletedAt
        {
            get => _deletedAt;
            set => _deletedAt = value;
        }

        public DateTime CreatedAt
        {
            get => _createdAt;
            set => _createdAt = value;
        }

        public DateTime? UpdatedAt
        {
            get => _updatedAt;
            set => _updatedAt = value;
        }

        public IReadOnlyList<ValidationResult> Validate()
        {
            var ctx     = new ValidationContext(this);
            var results = new List<ValidationResult>();
            Validator.TryValidateObject(this, ctx, results, validateAllProperties: true);
            return results;
        }

        public override string ToString() =>
            $"User[UserId={UserId}, PublicId={PublicId}, UserName=\"{UserName}\", Email=\"{UserEmail}\", AccessId={AccessId}]";

        public bool Equals(User? other)
        {
            if (other is null) return false;
            if (ReferenceEquals(this, other)) return true;
            if (_userId.HasValue && _userId > 0 && other._userId.HasValue && other._userId > 0)
                return _userId.Value == other._userId.Value;
            if (_guid.HasValue && _guid != Guid.Empty &&
                other._guid.HasValue && other._guid != Guid.Empty)
                return _guid.Value == other._guid.Value;
            return string.Equals(UserName, other.UserName, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object? obj) => Equals(obj as User);

        public override int GetHashCode()
        {
            if (_userId.HasValue && _userId > 0) return _userId.Value.GetHashCode();
            if (_guid.HasValue && _guid != Guid.Empty) return _guid.Value.GetHashCode();
            return HashCode.Combine(UserName.ToUpperInvariant());
        }

        private static string NormalizeSpaces(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return string.Empty;
            var parts = input.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            return string.Join(' ', parts);
        }
    }
}