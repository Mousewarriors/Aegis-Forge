#!/bin/bash
# Smoke Test: Aegis Forge Volume Mode & Canaries (Bash)

BASE_URL="http://localhost:8000"
CATEGORY="enumeration"

echo "🚀 Starting Smoke Test: Volume Mode & Canaries"

# 1. Trigger Campaign in VOLUME mode
echo "📦 Creating campaign in VOLUME mode..."
payload="{\"attack_category\": \"$CATEGORY\", \"mode\": \"A\", \"workspace_mode\": \"volume\", \"unsafe_dev\": false}"
resp=$(curl -s -X POST "$BASE_URL/campaigns" -H "Content-Type: application/json" -d "$payload")
cid=$(echo $resp | grep -oP '(?<="container_id":")[^"]+')
echo "✅ Container created: $cid"

# 4. Export Artifacts (Explicitly)
echo "📥 Exporting artifacts..."
export_payload="{\"container_id\": \"$cid\", \"path\": \"/workspace/output\", \"dest_name\": \"smoke-export.tar\"}"
export_resp=$(curl -s -X POST "$BASE_URL/campaigns/export" -H "Content-Type: application/json" -d "$export_payload")
host_path=$(echo $export_resp | grep -oP '(?<="host_path":")[^"]+')

if [ -f "$host_path" ]; then
    echo "✅ Export successful! Artifacts at: $host_path"
else
    echo "❌ Export failed or file not found at $host_path"
fi

echo "🧹 Cleanup happens automatically on campaign end."
echo "🏁 Smoke test finished."
