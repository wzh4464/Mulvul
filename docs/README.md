# Docs

The `docs/` directory is intentionally small.

Keep only the documents that explain the current repository shape:

- [MAINLINE_ARCHITECTURE.md](MAINLINE_ARCHITECTURE.md): the two first-class workflows
- [mainline_contracts.md](mainline_contracts.md): payload contracts, schemas, and fail-fast rules
- [ABLATIONS.md](ABLATIONS.md): what counts as an ablation and where legacy scripts live

Historical experiment notes, implementation diaries, and one-off integration
walkthroughs have been removed from `docs/`. If something needs to come back,
recover it from git history rather than growing the default docs surface again.
