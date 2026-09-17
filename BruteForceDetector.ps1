# ==========================================
# SOC Brute Force Detector
# Windows Event ID 4625
# ==========================================

$Threshold = 5
$TimeWindowMinutes = 5
$LookbackHours = 168

$EvidenceFolder = "C:\SOC-BruteForce\Evidence"

# Create evidence folder if it does not exist
New-Item -ItemType Directory -Path $EvidenceFolder -Force |
    Out-Null


# ------------------------------------------
# Get real Windows Event ID 4625 events
# ------------------------------------------

$StartTime = (Get-Date).AddHours(-$LookbackHours)

$Events = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue)


# ------------------------------------------
# No events found
# ------------------------------------------

if ($Events.Count -eq 0) {

    Write-Host ""
    Write-Host "No Event ID 4625 events found."
    Write-Host "Detector status: No alert"
    Write-Host ""

    exit
}


# ------------------------------------------
# Parse real events
# ------------------------------------------

$ParsedEvents = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()

    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID     = $Event.Id
        Account     = $Data.TargetUserName
        LogonType   = $Data.LogonType
        Status      = $Data.Status
        SubStatus   = $Data.SubStatus
        SourceIP    = $Data.IpAddress
        Process     = $Data.ProcessName
    }
}


$SortedEvents = $ParsedEvents | Sort-Object TimeCreated

$AlertFound = $false
$AlertWindow = $null


# ------------------------------------------
# Rolling 5-minute detection
# ------------------------------------------

foreach ($Event in $SortedEvents) {

    $WindowStart = $Event.TimeCreated
    $WindowEnd = $WindowStart.AddMinutes($TimeWindowMinutes)

    $WindowEvents = @(
        $SortedEvents | Where-Object {

            $_.SourceIP -eq $Event.SourceIP -and
            $_.Account -eq $Event.Account -and
            $_.TimeCreated -ge $WindowStart -and
            $_.TimeCreated -le $WindowEnd
        }
    )


    if ($WindowEvents.Count -ge $Threshold) {

        $AlertFound = $true
        $AlertWindow = $WindowEvents | Sort-Object TimeCreated

        break
    }
}


# ==========================================
# ALERT FOUND
# ==========================================

if ($AlertFound) {

    $FirstFailure = $AlertWindow | Select-Object -First 1
    $LastFailure  = $AlertWindow | Select-Object -Last 1

    $FailedLogons = $AlertWindow.Count

    if ($FailedLogons -ge 20) {
        $Severity = "Critical"
    }
    elseif ($FailedLogons -ge 10) {
        $Severity = "High"
    }
    else {
        $Severity = "Medium"
    }


    Write-Host ""
    Write-Host "========================================="
    Write-Host "       POTENTIAL BRUTE FORCE ALERT"
    Write-Host "========================================="
    Write-Host ""

    Write-Host "Source IP      : $($FirstFailure.SourceIP)"
    Write-Host "Target Account : $($FirstFailure.Account)"
    Write-Host "Failed Logons  : $FailedLogons"
    Write-Host "Window Start   : $($FirstFailure.TimeCreated)"
    Write-Host "Window End     : $($LastFailure.TimeCreated)"
    Write-Host "Threshold      : $Threshold"
    Write-Host "Severity       : $Severity"

    Write-Host ""
    Write-Host "Investigation:"
    Write-Host "Logon Type     : $($FirstFailure.LogonType)"
    Write-Host "Status         : $($FirstFailure.Status)"
    Write-Host "SubStatus      : $($FirstFailure.SubStatus)"
    Write-Host "Process        : $($FirstFailure.Process)"

    Write-Host ""
    Write-Host "Detector status: Alert"


    # --------------------------------------
    # Create alert evidence report
    # --------------------------------------

    $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

    $ReportPath = Join-Path $EvidenceFolder `
        "BruteForce_Alert_$Timestamp.txt"


    $Report = @"

=========================================
SOC BRUTE FORCE DETECTION REPORT
=========================================

Report Generated : $(Get-Date)

Detection Type   : Windows Event ID 4625
Detection Rule   : $Threshold failures within $TimeWindowMinutes minutes
Lookback Period  : $LookbackHours hours
Correlation      : Same Source IP + Same Target Account

-----------------------------------------
DETECTION SUMMARY
-----------------------------------------

Source IP        : $($FirstFailure.SourceIP)
Target Account   : $($FirstFailure.Account)
Failed Logons    : $FailedLogons
First Failure    : $($FirstFailure.TimeCreated)
Last Failure     : $($LastFailure.TimeCreated)
Severity         : $Severity

-----------------------------------------
EVENT DETAILS
-----------------------------------------

Event ID         : 4625
Logon Type       : $($FirstFailure.LogonType)
Status           : $($FirstFailure.Status)
SubStatus        : $($FirstFailure.SubStatus)
Process          : $($FirstFailure.Process)

-----------------------------------------
OBSERVED EVENTS
-----------------------------------------

"@


    foreach ($ObservedEvent in $AlertWindow) {

        $Report += @"
Time       : $($ObservedEvent.TimeCreated)
Event ID   : $($ObservedEvent.EventID)
Source IP  : $($ObservedEvent.SourceIP)
Account    : $($ObservedEvent.Account)

"@
    }


    $Report += @"
-----------------------------------------
ANALYST INVESTIGATION
-----------------------------------------

1. Verify whether the source IP is authorized.
2. Confirm whether the target account is expected.
3. Review surrounding Security events.
4. Check for successful logons following the failures.
5. Investigate related processes or network activity.
6. Escalate if the activity is unauthorized.

Assessment:
The detector identified repeated Event ID 4625 failures
matching the configured brute-force detection rule.

Further investigation is required to determine whether
the activity is malicious or legitimate.

=========================================
END OF REPORT
=========================================
"@


    $Report | Out-File -FilePath $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "Evidence report saved:"
    Write-Host $ReportPath
    Write-Host ""
}


# ==========================================
# NO ALERT FOUND
# ==========================================

else {

    $FirstEvent = $SortedEvents | Select-Object -First 1
    $LastEvent  = $SortedEvents | Select-Object -Last 1

    Write-Host ""
    Write-Host "========================================="
    Write-Host "       SOC INVESTIGATION SUMMARY"
    Write-Host "========================================="
    Write-Host ""

    Write-Host "4625 events found : $($SortedEvents.Count)"
    Write-Host "Lookback period   : $LookbackHours hours"
    Write-Host "Detection window  : $TimeWindowMinutes minutes"
    Write-Host "Threshold         : $Threshold failures"
    Write-Host ""

    Write-Host "First observed event : $($FirstEvent.TimeCreated)"
    Write-Host "Last observed event  : $($LastEvent.TimeCreated)"

    Write-Host ""
    Write-Host "Assessment:"
    Write-Host "No brute-force threshold was reached."
    Write-Host "Detector status: No alert"


    # --------------------------------------
    # Create no-alert investigation report
    # --------------------------------------

    $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

    $ReportPath = Join-Path $EvidenceFolder `
        "BruteForce_NoAlert_$Timestamp.txt"


    $Report = @"

=========================================
SOC BRUTE FORCE INVESTIGATION REPORT
=========================================

Report Generated : $(Get-Date)

Detection Type   : Windows Event ID 4625
Detection Rule   : $Threshold failures within $TimeWindowMinutes minutes
Lookback Period  : $LookbackHours hours
Correlation      : Same Source IP + Same Target Account

-----------------------------------------
INVESTIGATION SUMMARY
-----------------------------------------

Total 4625 Events : $($SortedEvents.Count)

First Event       : $($FirstEvent.TimeCreated)
Last Event        : $($LastEvent.TimeCreated)

Detection Status  : No Alert

-----------------------------------------
ASSESSMENT
-----------------------------------------

Event ID 4625 failures were found in the
Windows Security log.

The detector analyzed the events using a
rolling $TimeWindowMinutes-minute window.

No combination of the same Source IP and
same Target Account reached the configured
threshold of $Threshold failures.

Therefore, the configured brute-force
detection rule was not triggered.

-----------------------------------------
OBSERVED EVENTS
-----------------------------------------

"@
foreach ($ObservedEvent in $SortedEvents) {

    $Report += @"
TimeCreated : $($ObservedEvent.TimeCreated)
Event ID    : $($ObservedEvent.EventID)
Account     : $($ObservedEvent.Account)
Logon Type  : $($ObservedEvent.LogonType)
Status      : $($ObservedEvent.Status)
SubStatus   : $($ObservedEvent.SubStatus)
Source IP   : $($ObservedEvent.SourceIP)
Process     : $($ObservedEvent.Process)

"@
}

$Report += @"
-----------------------------------------
ANALYST NOTES
-----------------------------------------

1. Event ID 4625 indicates a failed logon.
2. Failed logons alone do not confirm brute-force activity.
3. Source IP and target account correlation was applied.
4. The threshold was not reached within the configured window.
5. No brute-force alert was generated.



-----------------------------------------
CONCLUSION
-----------------------------------------

No potential brute-force activity was detected
according to the current detection rule during
the configured lookback period.

This result does not prove that no suspicious
activity exists; it only indicates that the
defined detection condition was not met.

=========================================
END OF REPORT
=========================================
"@


    $Report | Out-File -FilePath $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "Investigation report saved:"
    Write-Host $ReportPath
    Write-Host ""
}