# Process_Injection
Whenever a process is created, modified, or executed, the script retrieves the process name and path, and then calls the Check-ProcessWithVirusTotal function to check if the process is detected as malicious. If it is, a message is sent to the specified Slack channel using the Send-SlackMessage function.
