# Function to monitor a process
function Monitor-Process($process) {
    # Initialize variables to store resource usage data
    $cpuUsages = @()
    $memUsages = @()
    $startTime = Get-Date

    # Create a performance counter to monitor CPU usage of the process
	$perfCounter = New-Object Diagnostics.PerformanceCounter("Process", "% Processor Time", $process.ProcessName, $true)

    # Monitor the process
    while (-not $process.HasExited) {
        $process.Refresh() # Refresh to get the latest process info

        # Collect CPU and Memory usage
        $cpuUsages += $perfCounter.NextValue() / [Environment]::ProcessorCount
        $memUsages += $process.WorkingSet64

        Start-Sleep -Milliseconds 500 # Sleep for a second or more depending on how often you want to collect data
    }
    $endTime = Get-Date
    $duration = $endTime - $startTime

    # Calculate Min, Max, and Avg for CPU and Memory
    $cpuAvg = ($cpuUsages | Measure-Object -Average).Average
    $memMin = ($memUsages | Measure-Object -Minimum).Minimum
    $memMax = ($memUsages | Measure-Object -Maximum).Maximum
    $memAvg = ($memUsages | Measure-Object -Average).Average

    # Convert memory usage to MB and round
    $memMinMB = [Math]::Round($memMin / 1MB)
    $memMaxMB = [Math]::Round($memMax / 1MB)
    $memAvgMB = [Math]::Round($memAvg / 1MB)

    # Output the results
    "Monitoring results:"
    "CPU Usage Percentage (Avg): $(($cpuAvg).ToString('N2'))%"
    "Memory Usage: Min = $($memMinMB) MB, Max = $($memMaxMB) MB, Avg = $($memAvgMB) MB"
    "Total Execution Time: $($duration.Days) Days, $($duration.Hours) Hours, $($duration.Minutes) Minutes, $($duration.Seconds) Seconds"
}

# Start and monitor the Rust File Decryptor program
<#"Rust - defender_file_decryptor.exe"
$rustExecutable = "defender_file_decryptor.exe"
$inputFileRust = "<sample_path_file>"
$outputFileRust = "<output_path_file>"
$rustProcess = Start-Process -FilePath $rustExecutable -ArgumentList "`"$inputFileRust`" `"$outputFileRust`"" -PassThru -NoNewWindow
Monitor-Process -process $rustProcess#>

# Start and monitor the Python File Decryptor script
<#"Python - MDE_Decode.py"
$pythonScript = "MDE_Decode.py"
$pythonProcess = Start-Process -FilePath "python.exe" -ArgumentList "`"$pythonScript`"" -PassThru -NoNewWindow
Monitor-Process -process $pythonProcess#>

# Start and monitor the compiled Python File Decryptor program
<#"AutoPy - MDE_Decode.exe"
$autoPyExecutable = "MDE_Decode.exe"
$autoPyProcess = Start-Process -FilePath $autoPyExecutable -PassThru -NoNewWindow
Monitor-Process -process $autoPyProcess#>
