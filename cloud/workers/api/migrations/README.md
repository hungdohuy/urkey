# D1 migrations

Forward-only SQL migrations for the `DB` binding, applied in file-name order
(`NNNN_description.sql`). Tables come from `docs/architecture/data-model.md` §3 and are added in
roadmap P3. Apply locally with `pnpm --filter api migrate:local`.
