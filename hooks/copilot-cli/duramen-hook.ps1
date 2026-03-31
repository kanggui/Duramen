# duramen pre-tool-use hook for Copilot CLI (PowerShell)
# Reads tool call payload from stdin, evaluates via duramen, returns permission decision.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DuramenBin = if (Test-Path (Join-Path $ScriptDir "duramen.exe")) {
    Join-Path $ScriptDir "duramen.exe"
} elseif (Test-Path (Join-Path $ScriptDir "duramen")) {
    Join-Path $ScriptDir "duramen"
} else {
    "duramen"
}

# Read raw stdin — Copilot CLI pipes JSON payload via stdin
# Use [Console]::In.ReadToEnd() because $input may be empty depending on how the script is invoked
$rawInput = [Console]::In.ReadToEnd()
$result = $rawInput | & $DuramenBin check --agent copilot-cli 2>$null
$exitCode = $LASTEXITCODE

switch ($exitCode) {
    0 {
        Write-Output '{"permissionDecision": "allow"}'
    }
    1 {
        $parsed = ($result -join "`n") | ConvertFrom-Json -ErrorAction SilentlyContinue
        $reason = if ($parsed.message) { $parsed.message } else { "Blocked by policy" }
        $policyName = $parsed.policy_name
        $policyDesc = $parsed.policy_description
        if ($policyName) {
            $reason = "$reason [$policyName"
            if ($policyDesc) { $reason = "${reason}: $policyDesc" }
            $reason = "$reason]"
        }
        $output = @{ permissionDecision = "deny"; permissionDecisionReason = $reason } | ConvertTo-Json -Compress
        Write-Output $output
    }
    2 {
        $parsed = ($result -join "`n") | ConvertFrom-Json -ErrorAction SilentlyContinue
        $reason = if ($parsed.message) { $parsed.message } else { "Requires approval" }
        $policyName = $parsed.policy_name
        $policyDesc = $parsed.policy_description
        if ($policyName) {
            $reason = "$reason [$policyName"
            if ($policyDesc) { $reason = "${reason}: $policyDesc" }
            $reason = "$reason]"
        }
        $output = @{ permissionDecision = "ask"; permissionDecisionReason = $reason } | ConvertTo-Json -Compress
        Write-Output $output
    }
    default {
        # Fail-closed on system errors — security systems must never fail-open
        Write-Output '{"permissionDecision": "deny", "permissionDecisionReason": "Duramen system error (fail-closed)"}'
    }
}
