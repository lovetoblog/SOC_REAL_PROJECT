# ==========================================
# SAFE LIVE MONITOR TEST
# Synthetic Event ID 4625
# ==========================================

Write-Host ""
Write-Host "========================================="
Write-Host "     LIVE MONITOR - SAFE TEST MODE"
Write-Host "========================================="
Write-Host ""
Write-Host "Watching Application log for synthetic Event ID 4625..."
Write-Host ""
Write-Host "Press Ctrl+C to stop."
Write-Host ""

$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.Logfile = 'Application' AND TargetInstance.EventCode = '4625'"

$Action = {

    $Event = $EventArgs.NewEvent.TargetInstance

    Write-Host ""
    Write-Host "========================================="
    Write-Host "      NEW SYNTHETIC EVENT DETECTED"
    Write-Host "========================================="
    Write-Host ""
    Write-Host "Event ID   : $($Event.EventCode)"
    Write-Host "Source     : $($Event.SourceName)"
    Write-Host "Computer   : $($Event.ComputerName)"
    Write-Host "Message    : $($Event.Message)"
    Write-Host ""
}

Register-WmiEvent `
    -Query $Query `
    -Action $Action `
    -ErrorAction Stop | Out-Null

try {

    while ($true) {
        Start-Sleep -Seconds 1
    }

}
finally {

    Get-EventSubscriber |
        Where-Object { $_.SourceIdentifier -like "WMI*" } |
        Unregister-Event `
        -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Test monitor stopped."
}