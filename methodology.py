"""Deterministic reference for one scenario family; never a model tool."""


def reference_disposition(cluster):
    identities = cluster["identity_uids"]
    if len(identities) > 1 or (identities and identities[0] != cluster["expected_identity_uid"]):
        return "ambiguous"
    if not identities:
        return "insufficient-evidence"
    disabled = cluster["disable_times"]
    cutoff = max(disabled) if disabled else cluster["termination_ms"]
    auth = [t for t in cluster["authentication_times"] if t > cutoff]
    web = [t for t in cluster["web_times"] if t > cutoff]
    if auth and web:
        return "candidate-submitted"
    if disabled and not auth and not web:
        return "contradicted"
    return "insufficient-evidence"
