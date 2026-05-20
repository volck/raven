#!/usr/bin/env bash
# find-invalid-sealedsecret-names.sh
#
# Scans the declarative/ tree for SealedSecret (and Secret) YAMLs whose
# metadata.name is not a valid RFC 1123 DNS subdomain — i.e. contains
# characters Kubernetes rejects (most commonly '/' from un-sanitized Vault
# paths, but also '_', uppercase, leading/trailing '-' or '.', etc.).
#
# Prints one file path per line on stdout. Exit code 0 if any invalid files
# were found, 1 if none. Side-effect free: never modifies files. To clean
# up, pipe into `git rm`, e.g.
#
#     scripts/find-invalid-sealedsecret-names.sh | xargs -r git rm
#
# Optional first arg overrides the search root (default: ./declarative).

set -euo pipefail

root="${1:-declarative}"

if [[ ! -d "$root" ]]; then
    echo "error: search root '$root' does not exist" >&2
    exit 2
fi

# RFC 1123 DNS subdomain: lowercase alphanumeric, '-' or '.', start/end
# alphanumeric, max 253 chars. We accept this as 'valid' and flag everything
# else.
rfc1123='^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'

found=0

# -print0 / read -d '' to survive any surprise whitespace in paths.
while IFS= read -r -d '' file; do
    # Extract the first top-level `name:` under metadata. We rely on the
    # 2-space indent convention used by Raven's serializer. Anything more
    # exotic should be reviewed manually.
    name="$(awk '
        /^metadata:/        { in_md = 1; next }
        in_md && /^[^[:space:]]/ { in_md = 0 }
        in_md && /^  name:/ { sub(/^  name:[[:space:]]*/, ""); print; exit }
    ' "$file")"

    [[ -z "$name" ]] && continue

    # Strip surrounding quotes if present.
    name="${name%\"}"
    name="${name#\"}"
    name="${name%\'}"
    name="${name#\'}"

    if [[ ${#name} -gt 253 ]] || ! [[ "$name" =~ $rfc1123 ]]; then
        printf '%s\n' "$file"
        found=1
    fi
done < <(find "$root" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0)

exit $(( found == 0 ? 1 : 0 ))
