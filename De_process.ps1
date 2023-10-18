# ان احسنت فمن الله و ان اسئت فمن نفسي والشيطان
# Prerequisites:
# - VirusTotal API key
# - Slack webhook URL

# Set your VirusTotal API key
$apiKey = "YOUR_VIRUSTOTAL_API_KEY"

# Set your Slack webhook URL
$webhookUrl = "YOUR_SLACK_WEBHOOK_URL"

# Function to send a message to Slack
function Send-SlackMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    $payload = @{
        text = $Message
    } | ConvertTo-Json
    
    Invoke-RestMethod -Uri $webhookUrl -Method POST -Body $payload -ContentType 'application/json'
}

# Function to query VirusTotal and check the process hash
function Check-ProcessWithVirusTotal {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ProcessName,
        
        [Parameter(Mandatory=$true)]
        [string]$ProcessPath
    )
    
    # Calculate the process hash
    $processHash = (Get-FileHash -Algorithm MD5 -Path $ProcessPath).Hash
    
    # Query VirusTotal for the process hash
    $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$processHash"
    $result = Invoke-RestMethod -Uri $url
    
    # Check if the process is detected as malicious
    if ($result.positives -gt 0) {
        $message = "Potentially malicious process detected:`n"
        $message += "Process Name: $ProcessName`n"
        $message += "Process Path: $ProcessPath`n"
        $message += "VirusTotal Detection Ratio: $($result.positives)/$($result.total)`n"
        $message += "VirusTotal Link: $($result.permalink)`n"
        
        Send-SlackMessage -Message $message
    }
}

# Event subscription for process creation, modification, and execution
$events = @(
    "__InstanceCreationEvent",
    "__InstanceModificationEvent",
    "__InstanceDeletionEvent",
    "__InstanceOperationEvent"
)

Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $event = $event.SourceEventArgs.NewEvent
    $processName = $event.ProcessName
    $processPath = $event.ExecutablePath
    
    Check-ProcessWithVirusTotal -ProcessName $processName -ProcessPath $processPath
}
