"""Helpers for explicitly gated legacy workflows."""


def ensure_legacy_three_layer_enabled(
    method: str,
    allow_legacy_script: bool,
) -> None:
    """Require an explicit opt-in before running legacy three-layer ablations."""
    if method != "mulvul":
        return
    if allow_legacy_script:
        return
    raise ValueError(
        "Legacy ablation path '--method mulvul' is disabled by default because "
        "its training loop does not optimize the full prompt bundle. Use the "
        "mainline workflows, or re-enable this ablation explicitly with "
        "--allow-legacy-script."
    )
