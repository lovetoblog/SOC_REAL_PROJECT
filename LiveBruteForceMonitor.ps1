# ==========================================
# SOC Brute Force Live Monitor V5
# Windows Event ID 4625
# ==========================================

$Threshold = 5
$TimeWindowMinutes = 5
$LookbackHours = 168

$EvidencePath = "C:\SOC-BruteForce\Evidence"
$SourceIdentifier = "SOC-BruteForce-Live"

# Make sure evidence directory exists
New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null

Write-Host ""
Write-Host "========================================="
Write-Host "      SOC BRUTE FORCE MONITOR V5"
Write-Host "========================================="
Write-Host ""
Write-Host "Detection Rule : $Threshold failures"
Write-Host "Time Window    : $TimeWindowMinutes minutes"
Write-Host "Lookback       : $LookbackHours hours"
Write-Host "Correlation    : Source IP + Target Account"
Write-Host "Evidence Path  : $EvidencePath"
Write-Host ""

# ------------------------------------------
# SEVERITY FUNCTION
# ------------------------------------------

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
# EVENT PARSER
# ------------------------------------------

function Convert-4625Event {

    param (
        $Event
    )

    [xml]$Xml = $Event.ToXml()

    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = $Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventID     = $Event.Id
        RecordId    = $Event.RecordId
        Account     = $Data.TargetUserName
        LogonType   = $Data.LogonType
        Status      = $Data.Status
        SubStatus   = $Data.SubStatus
        SourceIP    = $Data.IpAddress
        Process     = $Data.ProcessName
    }
}

# ------------------------------------------
# HISTORICAL ANALYSIS
# ------------------------------------------

$StartTime = (Get-Date).AddHours(-$LookbackHours)

$Events = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
)

Write-Host "Historical 4625 events found : $($Events.Count)"

if ($Events.Count -gt 0) {

    $ParsedEvents = foreach ($Event in $Events) {
        Convert-4625Event -Event $Event
    }

    $SortedEvents = @(
        $ParsedEvents | Sort-Object TimeCreated
    )

    $FirstEvent = $SortedEvents | Select-Object -First 1
    $LastEvent  = $SortedEvents | Select-Object -Last 1

    Write-Host "First event                  : $($FirstEvent.TimeCreated)"
    Write-Host "Last event                   : $($LastEvent.TimeCreated)"
}
else {

    $SortedEvents = @()

    Write-Host "No historical 4625 events found."
}

Write-Host ""
Write-Host "Historical assessment : No alert"

# ------------------------------------------
# LIVE EVENT STATE
# ------------------------------------------

$script:RecentEvents = @()
$script:LastAlertKey = ""
$script:LastAlertTime = [datetime]::MinValue

# ------------------------------------------
# LIVE EVENT ACTION
# ------------------------------------------

$Action = {

    # Configuration is intentionally inside
    # the event action to avoid scope problems.

    $LiveThreshold = 5
    $LiveWindowMinutes = 5
    $LiveEvidencePath = "C:\SOC-BruteForce\Evidence"

    $WmiEvent = $EventArgs.NewEvent.TargetInstance

    try {

        # ----------------------------------
        # GET EXACT EVENT
        # ----------------------------------

        $RecordId = [long]$WmiEvent.RecordNumber

        $RealEvent = Get-WinEvent `
            -LogName Security `
            -FilterXPath "*[System[(EventRecordID=$RecordId)]]" `
            -MaxEvents 1 `
            -ErrorAction Stop

        # ----------------------------------
        # PARSE EVENT XML
        # ----------------------------------

        [xml]$Xml = $RealEvent.ToXml()

        $Data = @{}

        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = $Item.'#text'
        }

        $NewEvent = [PSCustomObject]@{
            TimeCreated = $RealEvent.TimeCreated
            EventID     = $RealEvent.Id
            RecordId    = $RealEvent.RecordId
            Account     = $Data.TargetUserName
            LogonType   = $Data.LogonType
            Status      = $Data.Status
            SubStatus   = $Data.SubStatus
            SourceIP    = $Data.IpAddress
            Process     = $Data.ProcessName
        }

        # ----------------------------------
        # STORE EVENT
        # ----------------------------------

        $script:RecentEvents += $NewEvent

        # ----------------------------------
        # REMOVE OLD EVENTS
        # ----------------------------------

        $Cutoff = (Get-Date).AddMinutes(-$LiveWindowMinutes)

        $script:RecentEvents = @(
            $script:RecentEvents |
            Where-Object {
                $_.TimeCreated -ge $Cutoff
            }
        )

        # ----------------------------------
        # CORRELATE SOURCE + ACCOUNT
        # ----------------------------------

        $WindowEvents = @(
            $script:RecentEvents |
            Where-Object {
                $_.SourceIP -eq $NewEvent.SourceIP -and
                $_.Account -eq $NewEvent.Account
            } |
            Sort-Object TimeCreated
        )

        # ----------------------------------
        # DISPLAY NEW EVENT
        # ----------------------------------

        Write-Host ""
        Write-Host "-----------------------------------------"
        Write-Host "NEW SECURITY EVENT 4625"
        Write-Host "-----------------------------------------"
        Write-Host "Time       : $($NewEvent.TimeCreated)"
        Write-Host "Record ID  : $($NewEvent.RecordId)"
        Write-Host "Source IP  : $($NewEvent.SourceIP)"
        Write-Host "Account    : $($NewEvent.Account)"
        Write-Host "Logon Type : $($NewEvent.LogonType)"
        Write-Host "Failures   : $($WindowEvents.Count) / $LiveThreshold"
        Write-Host "Window     : $LiveWindowMinutes minutes"
        Write-Host ""

        # ----------------------------------
        # DETECTION
        # ----------------------------------

        if ($WindowEvents.Count -ge $LiveThreshold) {

            $Severity = if ($WindowEvents.Count -ge 20) {
                "Critical"
            }
            elseif ($WindowEvents.Count -ge 10) {
                "High"
            }
            else {
                "Medium"
            }

            $FirstFailure = $WindowEvents |
                Select-Object -First 1

            $LastFailure = $WindowEvents |
                Select-Object -Last 1

            # ----------------------------------
            # ALERT KEY
            # Prevent repeated reports for the
            # same source/account burst.
            # ----------------------------------

            $AlertKey = "$($NewEvent.SourceIP)|$($NewEvent.Account)"

            $ShouldCreateReport = $true

            if (
                $script:LastAlertKey -eq $AlertKey -and
                $script:LastAlertTime -ge $Cutoff
            ) {
                $ShouldCreateReport = $false
            }

            # ----------------------------------
            # DISPLAY ALERT
            # ----------------------------------

            Write-Host "========================================="
            Write-Host "       POTENTIAL BRUTE FORCE ALERT"
            Write-Host "========================================="
            Write-Host ""
            Write-Host "Source IP      : $($NewEvent.SourceIP)"
            Write-Host "Target Account : $($NewEvent.Account)"
            Write-Host "Failed Logons  : $($WindowEvents.Count)"
            Write-Host "Time Window    : $LiveWindowMinutes minutes"
            Write-Host "Threshold      : $LiveThreshold"
            Write-Host "Severity       : $Severity"
            Write-Host ""

            # ----------------------------------
            # CREATE LIVE EVIDENCE REPORT
            # ----------------------------------

            if ($ShouldCreateReport) {

                $ReportTime = Get-Date
                $Timestamp = $ReportTime.ToString("yyyy-MM-dd_HH-mm-ss")

                $ReportFile = Join-Path `
                    $LiveEvidencePath `
                    "LiveBruteForce_Alert_$Timestamp.txt"

                $Report = @"

=========================================
SOC BRUTE FORCE LIVE DETECTION REPORT
=========================================

Report Generated : $ReportTime

Detection Type   : Windows Event ID 4625
Detection Status : Potential Brute-Force Activity
Severity         : $Severity

Detection Rule   : $LiveThreshold failures within $LiveWindowMinutes minutes
Correlation      : Same Source IP + Same Target Account


-----------------------------------------
DETECTION SUMMARY
-----------------------------------------

Source IP        : $($NewEvent.SourceIP)
Target Account   : $($NewEvent.Account)
Failed Logons    : $($WindowEvents.Count)

First Failure    : $($FirstFailure.TimeCreated)
Last Failure     : $($LastFailure.TimeCreated)

Detection Window : $LiveWindowMinutes minutes
Threshold        : $LiveThreshold


-----------------------------------------
EVENT DETAILS
-----------------------------------------

Latest Event ID  : $($NewEvent.EventID)
Record ID        : $($NewEvent.RecordId)
Logon Type       : $($NewEvent.LogonType)
Status           : $($NewEvent.Status)
SubStatus        : $($NewEvent.SubStatus)
Process          : $($NewEvent.Process)


-----------------------------------------
OBSERVED EVENTS
-----------------------------------------

"@

                foreach ($ObservedEvent in $WindowEvents) {

                    $Report += @"
TimeCreated : $($ObservedEvent.TimeCreated)
Event ID    : $($ObservedEvent.EventID)
Record ID   : $($ObservedEvent.RecordId)
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
ANALYST INVESTIGATION
-----------------------------------------

1. Verify whether the source IP is authorized.
2. Verify whether the target account is expected.
3. Review surrounding Windows Security events.
4. Check for successful logons following the failures.
5. Review the logon type and authentication context.
6. Determine whether the activity is expected administrative or user activity.
7. Escalate for further investigation if the activity is unauthorized.


-----------------------------------------
ASSESSMENT
-----------------------------------------

The detector observed repeated Windows Event ID 4625
failures from the same Source IP and Target Account
within the configured detection window.

The threshold condition was reached.

This detection indicates potential brute-force activity.
Event ID 4625 alone does not prove that an attack occurred.


-----------------------------------------
RECOMMENDATION
-----------------------------------------

Investigate the source, target account, surrounding
authentication events, and any successful logons.

Correlate this alert with additional endpoint,
identity, or network telemetry before determining
whether the activity represents malicious behavior.


=========================================
END OF REPORT
=========================================

"@

                $Report | Out-File `
                    -FilePath $ReportFile `
                    -Encoding UTF8

                Write-Host "LIVE EVIDENCE REPORT CREATED"
                Write-Host "Report : $ReportFile"
                Write-Host ""

                $script:LastAlertKey = $AlertKey
                $script:LastAlertTime = $ReportTime
            }
            else {

                Write-Host "Evidence report already created for this"
                Write-Host "source/account burst."
                Write-Host ""
            }
        }

    }
    catch {

        Write-Host ""
        Write-Host "Live event parsing error:"
        Write-Host $_.Exception.Message
        Write-Host ""
    }
}

# ------------------------------------------
# WMI QUERY
# ------------------------------------------

$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.Logfile = 'Security' AND TargetInstance.EventCode = '4625'"

# ------------------------------------------
# CLEAN OLD SUBSCRIPTION
# ------------------------------------------

Get-EventSubscriber `
    -SourceIdentifier $SourceIdentifier `
    -ErrorAction SilentlyContinue |
    Unregister-Event `
    -Force `
    -ErrorAction SilentlyContinue

# ------------------------------------------
# START LIVE MONITOR
# ------------------------------------------

try {

    Register-WmiEvent `
        -Query $Query `
        -SourceIdentifier $SourceIdentifier `
        -Action $Action `
        -ErrorAction Stop | Out-Null

    Write-Host ""
    Write-Host "========================================="
    Write-Host "       LIVE MONITORING ACTIVE"
    Write-Host "========================================="
    Write-Host ""
    Write-Host "Watching Windows Security log..."
    Write-Host "Waiting for new Event ID 4625..."
    Write-Host ""
    Write-Host "Press Ctrl+C to stop monitoring."
    Write-Host ""

    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {

    Get-EventSubscriber `
        -SourceIdentifier $SourceIdentifier `
        -ErrorAction SilentlyContinue |
        Unregister-Event `
        -Force `
        -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Live monitor stopped."
}