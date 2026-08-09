using System.Collections.Concurrent;

namespace Api.Security
{

    public record PendingRegistration(
        string   Username,
        string   HashedPassword,
        DateTime ExpiresAt);

    public interface IPendingRegistrationStore
    {
        void                Save(string email, PendingRegistration reg);
        PendingRegistration? Get(string email);
        void                Remove(string email);
    }

    public class InMemoryPendingRegistrationStore : IPendingRegistrationStore
    {
        private readonly ConcurrentDictionary<string, PendingRegistration> _store =
            new(StringComparer.OrdinalIgnoreCase);

        public void Save(string email, PendingRegistration reg)
            => _store[email] = reg;

        public PendingRegistration? Get(string email)
        {
            if (_store.TryGetValue(email, out var reg))
            {
                if (DateTime.UtcNow <= reg.ExpiresAt)
                    return reg;

                _store.TryRemove(email, out _);
            }
            return null;
        }

        public void Remove(string email)
            => _store.TryRemove(email, out _);
    }
}
