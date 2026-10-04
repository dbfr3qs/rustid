-- Admin identity for configuration entities: an id distinct from the
-- natural key, and a version for optimistic concurrency (the admin model's
-- DataVersion). Existing rows get random ids; new ones get UUIDv7s.
ALTER TABLE identity_resources ADD COLUMN id uuid, ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE api_scopes         ADD COLUMN id uuid, ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE api_resources      ADD COLUMN id uuid, ADD COLUMN version integer NOT NULL DEFAULT 1;
ALTER TABLE clients            ADD COLUMN id uuid, ADD COLUMN version integer NOT NULL DEFAULT 1;
UPDATE identity_resources SET id = gen_random_uuid() WHERE id IS NULL;
UPDATE api_scopes         SET id = gen_random_uuid() WHERE id IS NULL;
UPDATE api_resources      SET id = gen_random_uuid() WHERE id IS NULL;
UPDATE clients            SET id = gen_random_uuid() WHERE id IS NULL;
ALTER TABLE identity_resources ALTER COLUMN id SET NOT NULL, ADD CONSTRAINT identity_resources_id UNIQUE (id);
ALTER TABLE api_scopes         ALTER COLUMN id SET NOT NULL, ADD CONSTRAINT api_scopes_id UNIQUE (id);
ALTER TABLE api_resources      ALTER COLUMN id SET NOT NULL, ADD CONSTRAINT api_resources_id UNIQUE (id);
ALTER TABLE clients            ALTER COLUMN id SET NOT NULL, ADD CONSTRAINT clients_id UNIQUE (id);
