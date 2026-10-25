-- Usernames are now normalised (Unicode NFKC, trimmed, lowercased) at creation
-- and at login, so "Alice" and "alice" are one account. Bring existing rows
-- into the same form, but never create a duplicate: where several rows
-- normalise to the same name, only the earliest-created one is renamed and the
-- others are left exactly as they are (kept, not deleted). A row left
-- un-normalised can no longer log in, because login normalises its input; the
-- operator should deactivate or recreate it. A WARNING names each such row.
--
-- Note: lower() follows the database's collation, so on a non-UTF8/"C" locale
-- non-ASCII capitals may not fold the same way JavaScript's toLowerCase does.
-- Such a row is simply left as it is.
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT id, username,
           lower(regexp_replace(normalize(username, NFKC), '^\s+|\s+$', '', 'g')) AS norm,
           row_number() OVER (
             PARTITION BY lower(regexp_replace(normalize(username, NFKC), '^\s+|\s+$', '', 'g'))
             ORDER BY created_at, id
           ) AS rank
    FROM local_users
  LOOP
    IF r.norm = r.username THEN
      CONTINUE;
    END IF;
    IF r.rank > 1 OR EXISTS (SELECT 1 FROM local_users o WHERE o.username = r.norm AND o.id <> r.id) THEN
      RAISE WARNING 'local user % (id %) collides with another account once normalised to %; left unchanged and unable to log in',
        r.username, r.id, r.norm;
    ELSE
      UPDATE local_users SET username = r.norm WHERE id = r.id;
    END IF;
  END LOOP;
END $$;
