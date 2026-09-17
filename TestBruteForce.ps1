# ==========================================
# Brute Force Detector - Controlled Test
# ==========================================

$Threshold = 5
$TimeWindowMinutes = 5

# CHANGE ONLY THIS NUMBER FOR TESTING
$TestEventCount = 4

# Keep events close enough to fit inside 5 minutes
$EventSpacingSeconds = 10


function Get-Severity {
    param (
        [int]$FailedLogons
    )

    if ($FailedLogons -ge 20) {
        return "Critical"
    }
    elseif ($FailedLogons -ge 10) {
        return "High"
    }
    elseif ($FailedLogons -ge 5) {
        return "Medium"
    }
    else {
        return "Low"
    }
}


# ------------------------------------------
# Generate controlled simulated events
# ------------------------------------------

$TestEvents = 0..($TestEventCount - 1) | ForEach-Object {

    [PSCustomObject]@{
        TimeCreated = (Get-Date).AddSeconds(-($_ * $EventSpacingSeconds))
        EventID     = 4625
        Account     = "testuser"
        LogonType   = 3
        Status      = "0xc000006d"
        SubStatus   = "0xc000006a"
        SourceIP    = "192.168.1.50"
        Process     = "test-process"
    }
}


# ------------------------------------------
# Apply same rolling-window logic
# as the real detector
# ------------------------------------------

$SortedEvents = $TestEvents | Sort-Object TimeCreated

$AlertFound = $false

foreach ($Event in $SortedEvents) {

    $WindowStart = $Event.TimeCreated
    $WindowEnd = $WindowStart.AddMinutes($TimeWindowMinutes)

    $WindowEvents = $SortedEvents | Where-Object {

        $_.SourceIP -eq $Event.SourceIP -and
        $_.Account -eq $Event.Account -and
        $_.TimeCreated -ge $WindowStart -and
        $_.TimeCreated -le $WindowEnd
    }


    if ($WindowEvents.Count -ge $Threshold) {

        $AlertFound = $true

        $WindowEvents = $WindowEvents | Sort-Object TimeCreated

        $FirstFailure = $WindowEvents | Select-Object -First 1
        $LastFailure  = $WindowEvents | Select-Object -Last 1

        # IMPORTANT:
        # Severity is based on the events that
        # actually triggered the detection.
        $Severity = Get-Severity -FailedLogons $WindowEvents.Count


        Write-Host ""
        Write-Host "========================================="
        Write-Host "       BRUTE FORCE DETECTION ALERT"
        Write-Host "========================================="
        Write-Host ""

        Write-Host "DETECTION SUMMARY"
        Write-Host "Source IP      : $($Event.SourceIP)"
        Write-Host "Target Account : $($Event.Account)"
        Write-Host "Failed Logons  : $($WindowEvents.Count)"
        Write-Host "Time Window    : $TimeWindowMinutes minutes"
        Write-Host "First Failure  : $($FirstFailure.TimeCreated)"
        Write-Host "Last Failure   : $($LastFailure.TimeCreated)"
        Write-Host "Threshold      : $Threshold"
        Write-Host "Severity       : $Severity"

        Write-Host ""
        Write-Host "INVESTIGATION DETAILS"
        Write-Host "Logon Type     : $($Event.LogonType)"
        Write-Host "Status         : $($Event.Status)"
        Write-Host "SubStatus      : $($Event.SubStatus)"
        Write-Host "Process        : $($Event.Process)"

        Write-Host ""
        Write-Host "ANALYST ACTION"
        Write-Host "1. Verify whether the source IP is authorized."
        Write-Host "2. Check whether the target account is expected."
        Write-Host "3. Review surrounding Security events."
        Write-Host "4. Look for successful logons after the failures."
        Write-Host "5. Escalate if the activity is unauthorized."

        Write-Host ""
        Write-Host "TEST STATUS"
        Write-Host "Controlled simulation - NOT a real attack."
        Write-Host ""

        break
    }
}


if (-not $AlertFound) {

    Write-Host ""
    Write-Host "No brute-force threshold reached."
    Write-Host "Events generated : $TestEventCount"
    Write-Host "Threshold        : $Threshold"
    Write-Host "Time Window      : $TimeWindowMinutes minutes"
    Write-Host ""
}