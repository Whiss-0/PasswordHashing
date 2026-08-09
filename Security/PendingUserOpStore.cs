using System;
using System.Collections.Concurrent;

namespace Api.Security
{
    // ── Pending Admin Registration ─────────────────────────────────────────────

    public record PendingAdminReg(
        string   Username,
        string   HashedPassword,
        string   Email,
        int      RoleId,
        DateTime ExpiresAt);

    public interface IPendingAdminRegStore
    {
        void              Save(Guid adminUserId, PendingAdminReg reg);
        PendingAdminReg?  Get(Guid adminUserId);
        void              Remove(Guid adminUserId);
    }

    public class InMemoryPendingAdminRegStore : IPendingAdminRegStore
    {
        private readonly ConcurrentDictionary<Guid, PendingAdminReg> _store = new();

        public void Save(Guid adminUserId, PendingAdminReg reg) => _store[adminUserId] = reg;

        public PendingAdminReg? Get(Guid adminUserId)
        {
            if (!_store.TryGetValue(adminUserId, out var reg)) return null;
            if (DateTime.UtcNow > reg.ExpiresAt) { _store.TryRemove(adminUserId, out _); return null; }
            return reg;
        }

        public void Remove(Guid adminUserId) => _store.TryRemove(adminUserId, out _);
    }

    // ── Pending User Delete ────────────────────────────────────────────────────

    public record PendingDeleteOp(Guid TargetUserId, DateTime ExpiresAt);

    // ── Pending User Update ────────────────────────────────────────────────────

    public record PendingUpdateOp(
        Guid     TargetUserId,
        string?  Username,
        string?  Email,
        int?     RoleId,
        string?  HashedPassword,
        DateTime ExpiresAt);

    // ── Pending User Restore ───────────────────────────────────────────────────

    public record PendingRestoreOp(Guid TargetUserId, DateTime ExpiresAt);

    public interface IPendingUserOpStore
    {
        void              SaveDelete(Guid adminUserId, PendingDeleteOp op);
        PendingDeleteOp?  GetDelete(Guid adminUserId);
        void              RemoveDelete(Guid adminUserId);

        void              SaveUpdate(Guid adminUserId, PendingUpdateOp op);
        PendingUpdateOp?  GetUpdate(Guid adminUserId);
        void              RemoveUpdate(Guid adminUserId);

        void              SaveRestore(Guid adminUserId, PendingRestoreOp op);
        PendingRestoreOp? GetRestore(Guid adminUserId);
        void              RemoveRestore(Guid adminUserId);
    }

    public class InMemoryPendingUserOpStore : IPendingUserOpStore
    {
        private readonly ConcurrentDictionary<Guid, PendingDeleteOp>  _deletes  = new();
        private readonly ConcurrentDictionary<Guid, PendingUpdateOp>  _updates  = new();
        private readonly ConcurrentDictionary<Guid, PendingRestoreOp> _restores = new();

        public void SaveDelete(Guid id, PendingDeleteOp op) => _deletes[id] = op;

        public PendingDeleteOp? GetDelete(Guid id)
        {
            if (!_deletes.TryGetValue(id, out var op)) return null;
            if (DateTime.UtcNow > op.ExpiresAt) { _deletes.TryRemove(id, out _); return null; }
            return op;
        }

        public void RemoveDelete(Guid id) => _deletes.TryRemove(id, out _);

        public void SaveUpdate(Guid id, PendingUpdateOp op) => _updates[id] = op;

        public PendingUpdateOp? GetUpdate(Guid id)
        {
            if (!_updates.TryGetValue(id, out var op)) return null;
            if (DateTime.UtcNow > op.ExpiresAt) { _updates.TryRemove(id, out _); return null; }
            return op;
        }

        public void RemoveUpdate(Guid id) => _updates.TryRemove(id, out _);

        public void SaveRestore(Guid id, PendingRestoreOp op) => _restores[id] = op;

        public PendingRestoreOp? GetRestore(Guid id)
        {
            if (!_restores.TryGetValue(id, out var op)) return null;
            if (DateTime.UtcNow > op.ExpiresAt) { _restores.TryRemove(id, out _); return null; }
            return op;
        }

        public void RemoveRestore(Guid id) => _restores.TryRemove(id, out _);
    }
}
