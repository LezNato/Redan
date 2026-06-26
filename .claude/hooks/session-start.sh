#!/usr/bin/env bash
# SessionStart: print the active engagement scope + RoE so every session
# opens with the authorization boundary in view. Read-only; never fails hard.
set -u
ROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
SCOPE="$ROOT/scope.yaml"

echo "=================================================================="
echo " Redan  —  authorized testing toolkit"
echo "=================================================================="
if [ ! -f "$SCOPE" ]; then
  echo " ⚠  No scope.yaml found. Define an engagement before active testing."
  echo "=================================================================="
  exit 0
fi

# Pull a few human-readable fields without a YAML parser.
# (strip the value, drop any trailing inline `# comment`, drop quotes)
field() { grep -E "^\s*$1:" "$SCOPE" | head -1 | sed -E "s/^\s*$1:\s*//; s/\s+#.*$//; s/\"//g; s/\s+$//"; }
name=$(field name)
type=$(field type)
auth=$(field authorization)

echo " Engagement : ${name:-<unset>}  (${type:-?})"
echo " Authorization: ${auth:-<unset>}"
echo " In scope   :"
awk '/^in_scope:/{f=1;next} /^[a-z_]+:/{f=0} f && /^\s*-/{print "   "$0}' "$SCOPE"
echo " Out of scope (hard-denied by the gate):"
awk '/^out_of_scope:/{f=1;next} /^[a-z_]+:/{f=0} f && /^\s*-/{print "   "$0}' "$SCOPE"
echo "------------------------------------------------------------------"
echo " Rule: every FINDING traces to a reproduction. No repro → it's a lead."
echo " The scope-gate hook blocks active calls to out-of-scope hosts."
echo "=================================================================="
exit 0
