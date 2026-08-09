using System;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

namespace Api.Security
{
    public static class PasswordHasher
    {
        private const int SaltSize = 32;
        private const int HashSize = 64;
        private const int MemorySize = 131072;
        private const int Iterations = 4;
        private const int Parallelism = 4;

        // Legacy constants — used before SaltSize/HashSize were increased.
        // Kept for backward-compatible verification of old hashes.
        private const int LegacySaltSize = 16;
        private const int LegacyHashSize = 32;

        public static string Hash(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password is required.");

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            var config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                Salt = salt,
                MemoryCost = MemorySize,
                TimeCost = Iterations,
                Lanes = Parallelism,
                Threads = Parallelism,
                HashLength = HashSize
            };

            using (var argon2A = new Argon2(config))
            {
                using (SecureArray<byte> hashA = argon2A.Hash())
                {
                    byte[] hash = hashA.Buffer;

                    // Storage format:
                    // base64(salt).base64(hash)
                    return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
                }
            }
        }

       
        public static bool IsHashed(string stored)
        {
            if (string.IsNullOrWhiteSpace(stored)) return false;
            var parts = stored.Split('.');
            if (parts.Length != 2) return false;
            try
            {
                var saltBytes = Convert.FromBase64String(parts[0]);
                var hashBytes = Convert.FromBase64String(parts[1]);

                // Accept both current and legacy hash sizes.
                bool isCurrentFormat = saltBytes.Length == SaltSize       && hashBytes.Length == HashSize;
                bool isLegacyFormat  = saltBytes.Length == LegacySaltSize && hashBytes.Length == LegacyHashSize;
                return isCurrentFormat || isLegacyFormat;
            }
            catch { return false; }
        }

        /// <summary>
        /// Returns true if <paramref name="stored"/> was produced with the old
        /// (SaltSize=16 / HashSize=32) parameters.
        /// </summary>
        public static bool IsLegacyHash(string stored)
        {
            if (string.IsNullOrWhiteSpace(stored)) return false;
            var parts = stored.Split('.');
            if (parts.Length != 2) return false;
            try
            {
                var saltBytes = Convert.FromBase64String(parts[0]);
                var hashBytes = Convert.FromBase64String(parts[1]);
                return saltBytes.Length == LegacySaltSize && hashBytes.Length == LegacyHashSize;
            }
            catch { return false; }
        }

        /// <summary>
        /// Verifies a password against a legacy hash (SaltSize=16, HashSize=32).
        /// After successful verification the caller should re-hash with <see cref="Hash"/> and persist.
        /// </summary>
        public static bool VerifyLegacy(string storedHash, string password)
        {
            if (string.IsNullOrWhiteSpace(storedHash) ||
                string.IsNullOrWhiteSpace(password))
                return false;

            var parts = storedHash.Split('.');
            if (parts.Length != 2) return false;

            byte[] salt;
            byte[] expectedHash;
            try
            {
                salt         = Convert.FromBase64String(parts[0]);
                expectedHash = Convert.FromBase64String(parts[1]);
            }
            catch { return false; }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            var config = new Argon2Config
            {
                Type       = Argon2Type.HybridAddressing,
                Version    = Argon2Version.Nineteen,
                Password   = passwordBytes,
                Salt       = salt,
                MemoryCost = MemorySize,
                TimeCost   = Iterations,
                Lanes      = Parallelism,
                Threads    = Parallelism,
                HashLength = LegacyHashSize
            };

            using (var argon2A = new Argon2(config))
            using (SecureArray<byte> hashA = argon2A.Hash())
            {
                return CryptographicOperations.FixedTimeEquals(hashA.Buffer, expectedHash);
            }
        }

      
        public static bool Verify(string storedHash, string password)
        {
            if (string.IsNullOrWhiteSpace(storedHash) ||
                string.IsNullOrWhiteSpace(password))
                return false;

            var parts = storedHash.Split('.');
            if (parts.Length != 2)
                return false;

            byte[] salt;
            byte[] expectedHash;

            try
            {
                salt = Convert.FromBase64String(parts[0]);
                expectedHash = Convert.FromBase64String(parts[1]);
            }
            catch
            {
              
                return false;
            }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            var config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                Password = passwordBytes,
                Salt = salt,
                MemoryCost = MemorySize,
                TimeCost = Iterations,
                Lanes = Parallelism,
                Threads = Parallelism,
                HashLength = HashSize
            };

            using (var argon2A = new Argon2(config))
            {
                using (SecureArray<byte> hashA = argon2A.Hash())
                {
                    byte[] actualHash = hashA.Buffer;

                    return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
                }
            }
        }
    }
}