#!/bin/sh
# Delete the files listed in prune.list from an installed environment.
#   prune.sh PYTHON PRUNE_LIST
# PYTHON is the environment's interpreter; globs in PRUNE_LIST are relative to its site-packages.
set -eu
py=$1
list=$2
site=$("$py" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
removed=0
while IFS= read -r line; do
    pat=${line%%#*}
    pat=$(printf '%s' "$pat" | tr -d '[:space:]')
    [ -n "$pat" ] || continue
    for f in "$site"/$pat; do
        if [ -e "$f" ]; then
            rm -f -- "$f"
            removed=$((removed + 1))
        fi
    done
done < "$list"
echo "pruned $removed file(s) listed in $(basename "$list")"
