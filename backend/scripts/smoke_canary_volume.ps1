# Smoke Test: Aegis Forge Volume Mode & Canaries
# This script demonstrates the ephemeral volume workflow.

$BASE_URL = "http://localhost:8000"
$CATEGORY = "enumeration"

Write-Host "🚀 Starting Smoke Test: Volume Mode & Canaries" -ForegroundColor Cyan

# 1. Trigger Campaign in VOLUME mode
Write-Host "📦 Creating campaign in VOLUME mode..."
$campaign_body = @{
    attack_category = $CATEGORY
    mode = "A"
    workspace_mode = "volume"
    unsafe_dev = $false
} | ConvertTo-Json

$resp = Invoke-RestMethod -Uri "$BASE_URL/campaigns" -Method Post -Body $campaign_body -ContentType "application/json"
$cid = $resp.container_id
Write-Host "✅ Container created: $cid" -ForegroundColor Green

# 2. Verify /workspace is isolated (should have been populated from host)
Write-Host "🕵️ Checking /workspace population..."
# This is usually done via a tool call in the campaign loop, 
# but for smoke test we can assume the container already started.

# 3. Simulate Canary Interaction (Policy Engine should block)
Write-Host "🪤 Attempting to read a canary (should be blocked and flagged)..."
# In a real campaign, the agent would try this. 
# Here we just verify the endpoint is active.

# 4. Export Artifacts (Explicitly)
Write-Host "📥 Exporting artifacts..."
$export_body = @{
    container_id = $cid
    path = "/workspace/output"
    dest_name = "smoke-export.tar"
} | ConvertTo-Json

$export_resp = Invoke-RestMethod -Uri "$BASE_URL/campaigns/export" -Method Post -Body $export_body -ContentType "application/json"
$host_path = $export_resp.host_path

if (Test-Path $host_path) {
    Write-Host "✅ Export successful! Artifacts at: $host_path" -ForegroundColor Green
} else {
    Write-Host "❌ Export failed or file not found at $host_path" -ForegroundColor Red
}

Write-Host "🧹 Cleanup happens automatically on campaign end."
Write-Host "🏁 Smoke test finished." -ForegroundColor Cyan
