# KEK rotation & backup/restore (runbook)

> Task T-M6-09 / T-M2-08 · SPEC §7 · remediation HIGH-6

astropath-dns-relay encrypts credentials at rest with a **key-encryption key (KEK)**
— Fernet + `MultiFernet` (`src/astropath/crypto.py`). This is *direct* key
encryption, deliberately **not** called "envelope" encryption (SPEC §7.2). Every
reversibly-stored secret (provider config, the HE per-record dynamic key, TSIG
secrets) is a Fernet token in the database; the plaintext exists only in memory at
point of use.

## Why rotation is cheap here

`ASTROPATH_CREDENTIAL_KEK` is an **ordered keylist** (primary first), not a single
key. `MultiFernet`:

- **encrypts** with the first (primary) key;
- **decrypts** by trying each key in list order, so ciphertext written by a
  retired key still decrypts after a new key is prepended;
- **`rotate(token)`** re-encrypts a token under the primary key while preserving
  its original creation timestamp.

Rotation is therefore a config change plus an optional bulk re-encrypt — **no
schema/version column, no downtime window**. At-rest decrypt passes **no `ttl`**
(SPEC §7.1); a `ttl` would spuriously reject aged stored secrets.

## Rotation procedure

1. **Generate a new Fernet key.**

   ```
   python -m astropath.bootstrap gen-kek
   # prints one urlsafe-base64 Fernet key — shown once; store it ansible-vault'd.
   ```

2. **Prepend it to the keylist** (comma- or whitespace-separated, primary first),
   keeping the retiring key in the list:

   ```
   ASTROPATH_CREDENTIAL_KEK="<NEW_KEY>,<OLD_KEY>"
   ```

   Deliver the keylist ansible-vault'd, never in git or logs.

3. **Rolling-restart** the service. `MultiFernet([new, old])` now *writes*
   new-key ciphertext and still *reads* old-key ciphertext, so the service is
   fully correct **before** any bulk migration runs. Startup fail-fast validates
   every keylist entry is a valid 32-byte urlsafe-base64 Fernet key (SPEC §11.3).

4. **Run the bulk re-encrypt pass** to migrate every stored ciphertext to the new
   primary. It is idempotent and safe to re-run. Programmatically:

   ```python
   from astropath.crypto import Kek
   from astropath.db import Database
   from astropath.rotation import rotate_stored_secrets

   kek = Kek.from_keylist(os.environ["ASTROPATH_CREDENTIAL_KEK"])  # new + old
   db = Database.from_dsn(os.environ["ASTROPATH_DATABASE_DSN"])
   async with db.session() as session:
       counts = await rotate_stored_secrets(session, kek)   # commits the session
   # counts.backends / counts.domains / counts.tsig_keys re-encrypted
   ```

   `rotate_stored_secrets` operates purely on opaque Fernet tokens — no plaintext
   is decrypted, logged, or returned. Domains with a NULL per-record secret
   (e.g. Route53) are skipped.

5. **Drop the retired key.** Once every ciphertext is migrated and verified, shrink
   the keylist to the new key alone and restart:

   ```
   ASTROPATH_CREDENTIAL_KEK="<NEW_KEY>"
   ```

Skipping step 4 is safe indefinitely (old ciphertext keeps decrypting) but the
retired key must remain in the list until the bulk pass has run — remove it only
after migration is confirmed.

## Backup & restore

- **Backup = two artifacts, stored separately:**
  1. the Postgres dump — **ciphertext only**, no plaintext secret;
  2. the KEK keylist — stored ansible-vault'd, separate from the dump.
  Restoring all secrets needs **both**.

- **A database dump alone restores nothing sensitive.** Provider / TSIG / HE
  secrets are KEK-encrypted (need the keylist) and API tokens / the admin password
  are one-way hashed and unrecoverable by design (SPEC §6.2). This encrypt-vs-hash
  guarantee is proven by the store tests (T-M2-03).

- **Restore:** load the ciphertext dump into Postgres, set
  `ASTROPATH_CREDENTIAL_KEK` to the matching keylist, and start the service. If the
  restored keylist no longer contains the key a token was written under, that
  token cannot be decrypted — keep retired keys in the vaulted backup until all
  ciphertext has been rotated forward.

## Future: OpenBao seam

A later Alembic revision may store only *references* in the encrypted columns and
fetch the real credentials from OpenBao at dispatch, reducing the crypto layer to a
thin adapter. Not in v1 (SPEC §7.3).

## Secret discipline

Only opaque ciphertext is read/written during rotation; no plaintext is decrypted,
logged, echoed, or persisted to a non-secret sink. Generated keys are shown once
and must be vaulted immediately (SPEC §7, §9.2).
