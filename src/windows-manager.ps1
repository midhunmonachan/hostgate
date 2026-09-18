# Fixed local platform adapter. Requests arrive on stdin, never as credential arguments.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Security
try {
  $q = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $sid = $identity.User.Value
  $isElevated = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  function Resolve-UserSid([string]$value) { if ($value -like "S-1-*") { return $value }; return ([Security.Principal.NTAccount]::new($value)).Translate([Security.Principal.SecurityIdentifier]).Value }
  switch ($q.action) {
    'secure' {
      [void][IO.Directory]::CreateDirectory($q.directory)
      $acl = [Security.AccessControl.DirectorySecurity]::new()
      $acl.SetAccessRuleProtection($true, $false)
      $acl.SetOwner($identity.User)
      foreach ($account in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
      }
      [IO.Directory]::SetAccessControl($q.directory, $acl)
      @{ ok = $true; sid = $sid; elevated = $isElevated } | ConvertTo-Json -Compress
    }
    'protect' {
      $plain = [Text.Encoding]::UTF8.GetBytes([string]$q.text)
      try {
        $cipher = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        @{ ciphertext = [Convert]::ToBase64String($cipher); sid = $sid } | ConvertTo-Json -Compress
      } finally { [Array]::Clear($plain, 0, $plain.Length) }
    }
    'unprotect' {
      $cipher = [Convert]::FromBase64String([string]$q.ciphertext)
      $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
      try { @{ text = [Text.Encoding]::UTF8.GetString($plain); sid = $sid } | ConvertTo-Json -Compress }
      finally { [Array]::Clear($plain, 0, $plain.Length) }
    }
    'inspect-task' {
      $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
      $task = $null
      try { $task = $svc.GetFolder('\').GetTask([string]$q.name) } catch {}
      if ($null -eq $task) { @{ exists = $false } | ConvertTo-Json -Compress; break }
      $def = $task.Definition
      $action = $def.Actions.Item(1)
      $userSid = $def.Principal.UserId
      if ($userSid -notlike 'S-1-*') { $userSid = ([Security.Principal.NTAccount]::new($userSid)).Translate([Security.Principal.SecurityIdentifier]).Value }
      @{ exists = $true; enabled = [bool]$task.Enabled; state = [int]$task.State;
        executable = $action.Path; arguments = $action.Arguments; user = $userSid;
        logonType = [int]$def.Principal.LogonType; runLevel = [int]$def.Principal.RunLevel;
        logonTrigger = [bool](@($def.Triggers | Where-Object { $_.Type -eq 9 -and (Resolve-UserSid $_.UserId) -eq $sid }).Count);
        restartInterval = $def.Settings.RestartInterval; restartCount = $def.Settings.RestartCount;
        executionTimeLimit = $def.Settings.ExecutionTimeLimit; lastResult = $task.LastTaskResult } | ConvertTo-Json -Compress
    }
    'install-task' {
      $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect(); $folder = $svc.GetFolder('\')
      $existing = $null
      try { $existing = $folder.GetTask([string]$q.name) } catch {}
      if ($null -ne $existing) { throw 'Existing task must be inspected, not overwritten.' }
      $def = $svc.NewTask(0)
      $def.RegistrationInfo.Description = 'Hostgate user-logon supervisor; full authorized access under the current Windows account.'
      $def.Principal.UserId = $sid
      $def.Principal.LogonType = 3 # InteractiveToken: no password stored, starts at this user's logon.
      $def.Principal.RunLevel = 0 # Same account, non-elevated. Never silently switch identities.
      $def.Settings.Enabled = $true
      $def.Settings.StartWhenAvailable = $true
      $def.Settings.DisallowStartIfOnBatteries = $false
      $def.Settings.StopIfGoingOnBatteries = $false
      $def.Settings.ExecutionTimeLimit = 'PT0S'
      $def.Settings.MultipleInstances = 2 # IgnoreNew
      $def.Settings.RestartInterval = 'PT1M'
      $def.Settings.RestartCount = 999
      $trigger = $def.Triggers.Create(9)
      $trigger.UserId = $sid; $trigger.Enabled = $true; $trigger.Delay = 'PT5S'
      $action = $def.Actions.Create(0)
      $action.Path = [string]$q.executable
      $action.Arguments = [string]$q.arguments
      $action.WorkingDirectory = [string]$q.directory
      [void]$folder.RegisterTaskDefinition([string]$q.name, $def, 2, $sid, $null, 3) # CREATE only
      @{ ok = $true; sid = $sid } | ConvertTo-Json -Compress
    }
    'start-task' {
      $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
      [void]$svc.GetFolder('\').GetTask([string]$q.name).Run($null)
      @{ ok = $true } | ConvertTo-Json -Compress
    }
    'process' {
      $p = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$q.pid)
      if ($null -eq $p) { @{ exists = $false } | ConvertTo-Json -Compress; break }
      $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
      @{ exists = $true; pid = $p.ProcessId; executable = $p.ExecutablePath; commandLine = $p.CommandLine;
        started = $p.CreationDate.ToUniversalTime().ToString('o'); sid = $owner.Sid } | ConvertTo-Json -Compress
    }
    'stop-exact' {
      $p = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$q.pid)
      if ($null -eq $p) { @{ ok = $true; alreadyExited = $true } | ConvertTo-Json -Compress; break }
      $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
      if ($owner.Sid -ne $sid -or $p.CreationDate.ToUniversalTime().ToString('o') -ne $q.started -or $p.ExecutablePath -ne $q.executable -or $p.CommandLine -ne $q.commandLine) {
        throw 'Process identity changed; refusing to stop it.'
      }
      # Stop only this verified PID, not its process tree or unrelated sessions.
      Stop-Process -Id $p.ProcessId -ErrorAction Stop
      @{ ok = $true } | ConvertTo-Json -Compress
    }
    default { throw 'Unknown local manager operation.' }
  }
} catch {
  # Never include DPAPI input, process environment, or raw exception content in diagnostics.
  [Console]::Error.WriteLine('Windows manager operation failed: ' + [string]$q.action)
  exit 1
}
