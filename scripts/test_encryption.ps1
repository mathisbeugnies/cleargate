$proxy = "http://localhost:8080"
$target = "http://example.com"

# data with secrets
$body = @{
    prompt = "My API Key is sk-abcdef1234567890 and email is secret@corp.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri $target -Method Post -Body $body -Proxy $proxy -ContentType "application/json" -Headers @{"X-ClearGate-User"="admin@cleargate.com"; "X-ClearGate-Key"="secret"}
Write-Host "Request sent via Proxy. Check Audit Logs in Dashboard."
