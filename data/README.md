# Data layout

- `public/` is the only dataset intended for artifact release.
- The original `users/` collection at the repository root is restricted source
  data and is intentionally absent from sanitized release archives.
- `User_Manager/data/` is local runtime state created by new demo sessions and is
  also excluded from release.

See `ETHICS_AND_DATA.md` at the repository root for the handling rationale.
