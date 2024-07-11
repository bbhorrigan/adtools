# Define the time window for the event search (last 30 minutes)
$startTime = [datetime]::Now.AddMinutes(-30)

# Define the filter hashtable to search for event ID 4740 in the Security log
$filterHashTable = @{
    LogName = 'Security'   # Log name
    Id = 4740              # Event ID for user account lockout
    StartTime = $startTime # Start time for the search window
}

# Use Get-WinEvent to retrieve the events from the specified computer (dc1)
Get-WinEvent -FilterHashtable $filterHashTable -ComputerName dc1 |
    Select-Object TimeCreated,                             # Select the time the event was created
                  @{Name = 'Account'; Expression = { $_.Properties[0].Value }},  # Select the account name
                  @{Name = 'From'; Expression = { $_.Properties[1].Value }}     # Select the source of the lockout
