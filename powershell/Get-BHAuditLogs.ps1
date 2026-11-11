#Requires -Version 5.1
<#
.SYNOPSIS
Exports BloodHound audit logs through GET /api/v2/audit.

.DESCRIPTION
Supports signed API tokens or bearer JWTs; relative or
absolute UTC time ranges; API filters; full-record text search; pagination;
and table, JSON, JSON Lines, or CSV output.
#>
[CmdletBinding()]
param(
    [string]$Config,
    [switch]$Interactive,
    [string]$Url,
    [string]$TokenId,
    [string]$TokenKey,
    [string]$BearerToken,
    [switch]$NoPrompt,
    [Nullable[double]]$Days,
    [Nullable[double]]$Hours,
    [string]$Start,
    [string]$End,
    [string]$ActorId,
    [string]$ActorName,
    [string]$ActorEmail,
    [string]$Action,
    [string]$RequestId,
    [string]$Source,
    [ValidateSet('intent', 'success', 'failure')][string]$Status,
    [string]$Search,
    [Nullable[int]]$PageSize,
    [ValidateRange(0, [int]::MaxValue)][int]$MaxRecords = 0,
    [ValidateSet('table', 'json', 'jsonl', 'csv')][string]$OutputFormat,
    [string]$OutputFile,
    [Nullable[int]]$Timeout,
    [Nullable[int]]$MaxRetries,
    [Nullable[double]]$RetryDelay,
    [Alias('Insecure')][switch]$SkipCertificateCheck,
    [switch]$NoSummary
)

$script:BHApiPath = '/api/v2/audit'
$script:BHCsvColumns = @(
    'id', 'created_at', 'actor_id', 'actor_name', 'actor_email', 'action',
    'status', 'request_id', 'source_ip_address', 'commit_id', 'fields_json'
)

function ConvertTo-BHRfc3339 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][datetime]$Value)
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-BHDateTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [switch]$EndOfDate
    )
    $text = $Value.Trim()
    try {
        if ($text -match '^\d{4}-\d{2}-\d{2}$') {
            $parsed = [datetime]::ParseExact(
                $text,
                'yyyy-MM-dd',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None
            )
            $parsed = [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
            if ($EndOfDate) { $parsed = $parsed.AddDays(1) }
            return $parsed
        }
        if ($text -match '(?i)(Z|[+-]\d{2}:\d{2})$') {
            $offset = [datetimeoffset]::Parse(
                $text,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            return $offset.UtcDateTime
        }
        $parsed = [datetime]::Parse(
            $text,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AllowWhiteSpaces
        )
        return [datetime]::SpecifyKind($parsed, [DateTimeKind]::Utc)
    }
    catch {
        throw "Invalid date/time '$Value'. Use ISO-8601/RFC3339."
    }
}

function Resolve-BHTimeRange {
    [CmdletBinding()]
    param(
        [Nullable[double]]$Days,
        [Nullable[double]]$Hours,
        [string]$Start,
        [string]$End,
        [double]$DefaultDays = 7,
        [datetime]$Now = ([datetime]::UtcNow)
    )
    $relativeCount = [int]($null -ne $Days) + [int]($null -ne $Hours)
    $absoluteUsed = -not [string]::IsNullOrWhiteSpace($Start) -or -not [string]::IsNullOrWhiteSpace($End)
    if ($relativeCount -gt 1 -or ($relativeCount -gt 0 -and $absoluteUsed)) {
        throw 'Use only one time mode: -Days, -Hours, or -Start with -End.'
    }
    if ($absoluteUsed) {
        if ([string]::IsNullOrWhiteSpace($Start) -or [string]::IsNullOrWhiteSpace($End)) {
            throw 'Absolute time ranges require both -Start and -End.'
        }
        $after = ConvertFrom-BHDateTime -Value $Start
        $before = ConvertFrom-BHDateTime -Value $End -EndOfDate
    }
    else {
        if ($null -ne $Days) {
            if ([double]$Days -le 0) { throw '-Days must be greater than zero.' }
            $span = [timespan]::FromDays([double]$Days)
        }
        elseif ($null -ne $Hours) {
            if ([double]$Hours -le 0) { throw '-Hours must be greater than zero.' }
            $span = [timespan]::FromHours([double]$Hours)
        }
        else {
            if ($DefaultDays -le 0) { throw 'default_days must be greater than zero.' }
            $span = [timespan]::FromDays($DefaultDays)
        }
        $before = $Now.ToUniversalTime()
        $after = $before.Subtract($span)
    }
    if ($after -ge $before) { throw 'The start of the time range must be before the end.' }
    return [pscustomobject]@{ After = $after; Before = $before }
}

function Invoke-BHHmacSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Data
    )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $Key)
    try { return $hmac.ComputeHash($Data) }
    finally { $hmac.Dispose() }
}

function New-BHSignedHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$TokenId,
        [Parameter(Mandatory)][string]$TokenKey,
        [AllowNull()][string]$Body = '',
        [datetime]$RequestTime = ([datetime]::UtcNow)
    )
    $timestamp = ConvertTo-BHRfc3339 -Value $RequestTime
    $utf8 = [Text.Encoding]::UTF8
    $operationDigest = Invoke-BHHmacSha256 -Key $utf8.GetBytes($TokenKey) -Data $utf8.GetBytes(('{0}{1}' -f $Method.ToUpperInvariant(), $Uri))
    $dateDigest = Invoke-BHHmacSha256 -Key $operationDigest -Data $utf8.GetBytes($timestamp.Substring(0, 13))
    $bodyText = if ($null -eq $Body) { '' } else { $Body }
    $bodyDigest = Invoke-BHHmacSha256 -Key $dateDigest -Data $utf8.GetBytes($bodyText)
    return @{
        Authorization = "bhesignature $TokenId"
        RequestDate   = $timestamp
        Signature     = [Convert]::ToBase64String($bodyDigest)
    }
}

function ConvertTo-BHQueryUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][object[]]$QueryPairs = @()
    )
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pair in $QueryPairs) {
        if ($null -eq $pair -or $null -eq $pair.Value) { continue }
        $parts.Add(('{0}={1}' -f [uri]::EscapeDataString([string]$pair.Name), [uri]::EscapeDataString([string]$pair.Value)))
    }
    if ($parts.Count -eq 0) { return $Path }
    return '{0}?{1}' -f $Path, ($parts -join '&')
}

function Get-BHRetryDelay {
    param([int]$Attempt, [string]$RetryAfter, [double]$BaseDelay)
    if (-not [string]::IsNullOrWhiteSpace($RetryAfter)) {
        $seconds = 0.0
        if ([double]::TryParse($RetryAfter, [ref]$seconds)) {
            return [Math]::Min([Math]::Max(0, $seconds), 60)
        }
    }
    return [Math]::Min($BaseDelay * [Math]::Pow(2, $Attempt), 60)
}

function Invoke-BHJsonRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET')][string]$Method,
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][string]$Path,
        [object[]]$QueryPairs = @(),
        [string]$BearerToken,
        [string]$TokenId,
        [string]$TokenKey,
        [int]$TimeoutSeconds = 30,
        [int]$MaxRetries = 3,
        [double]$RetryDelaySeconds = 1,
        [switch]$SkipCertificateCheck
    )
    $apiUri = ConvertTo-BHQueryUri -Path $Path -QueryPairs $QueryPairs
    $requestUrl = $BaseUrl.TrimEnd('/') + $apiUri
    $body = $null
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $headers = @{ Accept = 'application/json'; 'User-Agent' = 'GetBHEAuditLogs-PowerShell/1.0' }
        if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
            $headers.Authorization = "Bearer $BearerToken"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($TokenId) -and -not [string]::IsNullOrWhiteSpace($TokenKey)) {
            $signed = New-BHSignedHeaders -Method $Method -Uri $apiUri -TokenId $TokenId -TokenKey $TokenKey -Body $body
            foreach ($key in $signed.Keys) { $headers[$key] = $signed[$key] }
        }
        else { throw 'Authenticated request attempted without complete credentials.' }
        $parameters = @{
            Method      = $Method
            Uri         = $requestUrl
            Headers     = $headers
            TimeoutSec  = $TimeoutSeconds
            ErrorAction = 'Stop'
        }
        Write-Verbose ("{0} {1} (attempt {2})" -f $Method, $apiUri, ($attempt + 1))
        $previousCallback = $null
        try {
            if ($SkipCertificateCheck) {
                $previousCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
                [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            return Invoke-RestMethod @parameters
        }
        catch {
            $response = $_.Exception.Response
            $statusCode = if ($null -ne $response -and $null -ne $response.StatusCode) { [int]$response.StatusCode } else { 0 }
            if ($statusCode -in @(429, 502, 503, 504) -and $attempt -lt $MaxRetries) {
                $retryAfter = if ($null -ne $response) { [string]$response.Headers['Retry-After'] } else { $null }
                $delay = Get-BHRetryDelay -Attempt $attempt -RetryAfter $retryAfter -BaseDelay $RetryDelaySeconds
                Write-Verbose ("HTTP {0}; retrying in {1:g}s" -f $statusCode, $delay)
                Start-Sleep -Milliseconds ([int]($delay * 1000))
                continue
            }
            if ($statusCode -eq 0 -and $attempt -lt $MaxRetries) {
                $delay = Get-BHRetryDelay -Attempt $attempt -BaseDelay $RetryDelaySeconds
                Write-Verbose ("Network error; retrying in {0:g}s" -f $delay)
                Start-Sleep -Milliseconds ([int]($delay * 1000))
                continue
            }
            $hint = switch ($statusCode) {
                400 { ' Check the time range and filter values.' }
                401 { ' Check the authentication values and token/JWT validity.' }
                403 { ' The authenticated principal may lack permission to read audit logs.' }
                default { '' }
            }
            if ($statusCode) { throw "BloodHound returned HTTP $statusCode.$hint $($_.Exception.Message)" }
            throw "Could not reach BloodHound: $($_.Exception.Message)"
        }
        finally {
            if ($SkipCertificateCheck) {
                [Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
            }
        }
    }
    throw 'Request failed after all retry attempts.'
}

function New-BHQueryPair {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    return [pscustomobject]@{ Name = $Name; Value = $Value }
}

function ConvertTo-BHExactFilter {
    param([Parameter(Mandatory)][string]$Name, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value.Contains(':')) { throw "$Name cannot contain ':' when used as an exact API filter." }
    return "eq:$Value"
}

function New-BHBaseQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$After,
        [Parameter(Mandatory)][datetime]$Before,
        [hashtable]$Filters = @{}
    )
    $pairs = New-Object 'System.Collections.Generic.List[object]'
    $pairs.Add((New-BHQueryPair -Name after -Value (ConvertTo-BHRfc3339 $After)))
    $pairs.Add((New-BHQueryPair -Name before -Value (ConvertTo-BHRfc3339 $Before)))
    $pairs.Add((New-BHQueryPair -Name sort_by -Value '-created_at'))
    $pairs.Add((New-BHQueryPair -Name sort_by -Value '-id'))
    foreach ($name in @('actor_id', 'actor_name', 'actor_email', 'action', 'request_id', 'source')) {
        $filtered = ConvertTo-BHExactFilter -Name $name -Value ([string]$Filters[$name])
        if ($null -ne $filtered) { $pairs.Add((New-BHQueryPair -Name $name -Value $filtered)) }
    }
    if ($Filters.status -in @('success', 'failure')) {
        $pairs.Add((New-BHQueryPair -Name status -Value ("eq:{0}" -f $Filters.status)))
    }
    return ,$pairs.ToArray()
}

function Test-BHAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [string]$Search,
        [string]$Status
    )
    if (-not [string]::IsNullOrWhiteSpace($Status) -and [string]$Record.status -ine $Status) { return $false }
    if ([string]::IsNullOrWhiteSpace($Search)) { return $true }
    $json = $Record | ConvertTo-Json -Compress -Depth 50
    return $json.IndexOf($Search, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-BHAuditLogPages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$RequestPage,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BaseQuery,
        [int]$PageSize = 500,
        [int]$MaxRecords = 0,
        [string]$Search,
        [string]$Status,
        [scriptblock]$RecordSink
    )
    if ($PageSize -le 0) { throw 'PageSize must be greater than zero.' }
    if ($MaxRecords -lt 0) { throw 'MaxRecords cannot be negative.' }
    $fetched = 0
    $expectedTotal = $null
    $previousPageJson = $null
    $matchedCount = 0
    $matched = New-Object 'System.Collections.Generic.List[object]'
    while ($true) {
        $remaining = if ($MaxRecords) { $MaxRecords - $fetched } else { $PageSize }
        $requestLimit = if ($MaxRecords) { [Math]::Min($PageSize, $remaining) } else { $PageSize }
        if ($requestLimit -le 0) { break }
        $pageQuery = New-Object 'System.Collections.Generic.List[object]'
        foreach ($pair in $BaseQuery) { $pageQuery.Add($pair) }
        $pageQuery.Add((New-BHQueryPair -Name skip -Value ([string]$fetched)))
        $pageQuery.Add((New-BHQueryPair -Name limit -Value ([string]$requestLimit)))
        $response = & $RequestPage -QueryPairs $pageQuery.ToArray()
        if ($null -eq $response -or $null -eq $response.data -or $null -eq $response.data.logs) {
            throw 'Response did not contain data.logs.'
        }
        if ($response.data.logs -isnot [array]) { throw 'Response data.logs was not an array.' }
        $logs = $response.data.logs
        foreach ($record in $logs) {
            if ($null -eq $record -or ($record -isnot [pscustomobject] -and $record -isnot [System.Collections.IDictionary])) {
                throw 'Response data.logs contained a record that was not an object.'
            }
        }
        if ($logs.Count -gt $requestLimit) { throw 'Response contained more records than the requested limit.' }
        if ($null -ne $response.PSObject.Properties['skip']) {
            if (($response.skip -isnot [int] -and $response.skip -isnot [long]) -or $response.skip -ne $fetched) {
                throw 'Response skip did not match the requested offset.'
            }
        }
        if ($null -ne $response.PSObject.Properties['count']) {
            if (($response.count -isnot [int] -and $response.count -isnot [long]) -or $response.count -lt 0) {
                throw 'Response count must be a non-negative integer.'
            }
            if ($null -eq $expectedTotal) { $expectedTotal = [long]$response.count }
        }
        $pageJson = ConvertTo-Json -InputObject $logs -Depth 50 -Compress
        if ($logs.Count -gt 0 -and $pageJson -ceq $previousPageJson) {
            throw 'BloodHound repeated the previous page; pagination made no progress.'
        }
        $previousPageJson = $pageJson
        $fetched += $logs.Count
        foreach ($record in $logs) {
            if (Test-BHAuditRecord -Record $record -Search $Search -Status $Status) {
                $matchedCount++
                if ($null -ne $RecordSink) { & $RecordSink $record | Out-Null }
                else { $matched.Add($record) }
            }
        }
        Write-Verbose ("Fetched {0}/{1}; matched {2}" -f $fetched, $(if ($null -eq $expectedTotal) { 'unknown' } else { $expectedTotal }), $matchedCount)
        # Older releases may report counts outside the date range. A short page
        # may also reflect a server cap, so continue until an empty page.
        if ($logs.Count -eq 0) {
            if ($null -ne $expectedTotal -and $fetched -ne $expectedTotal) {
                [Console]::Error.WriteLine(('Warning: API count was {0}, but pagination returned {1} records. Older BloodHound releases may report inaccurate date-range counts; verify the server version and export completeness.' -f $expectedTotal, $fetched))
            }
            break
        }
        if ($MaxRecords -and $fetched -ge $MaxRecords) { break }
    }
    return [pscustomobject]@{ Logs = @($matched.ToArray()); Fetched = $fetched; MatchedCount = $matchedCount }
}

function ConvertTo-BHCsv {
    [CmdletBinding()]
    param([object[]]$Logs)
    $rows = foreach ($record in @($Logs)) {
        [pscustomobject][ordered]@{
            id                = $record.id
            created_at        = $record.created_at
            actor_id          = $record.actor_id
            actor_name        = $record.actor_name
            actor_email       = $record.actor_email
            action            = $record.action
            status            = $record.status
            request_id        = $record.request_id
            source_ip_address = $record.source_ip_address
            commit_id         = $record.commit_id
            fields_json       = ($record.fields | ConvertTo-Json -Compress -Depth 50)
        }
    }
    if (@($rows).Count -eq 0) {
        return (($script:BHCsvColumns | ForEach-Object { '"{0}"' -f $_ }) -join ',') + [Environment]::NewLine
    }
    return ((@($rows) | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine) + [Environment]::NewLine
}

function ConvertTo-BHTable {
    [CmdletBinding()]
    param([object[]]$Logs)
    if (@($Logs).Count -eq 0) { return 'No audit logs matched.' + [Environment]::NewLine }
    $columns = @('created_at', 'actor_name', 'action', 'status', 'source_ip_address')
    $maximums = @{ created_at = 27; actor_name = 24; action = 32; status = 8; source_ip_address = 30 }
    $widths = @{}
    foreach ($column in $columns) { $widths[$column] = $column.Length }
    $rows = foreach ($record in $Logs) {
        $row = @{}
        foreach ($column in $columns) {
            $value = ([string]$record.$column).Replace("`r", ' ').Replace("`n", ' ')
            $maximum = $maximums[$column]
            if ($value.Length -gt $maximum) { $value = $value.Substring(0, $maximum - 1) + [char]0x2026 }
            $row[$column] = $value
            $widths[$column] = [Math]::Max($widths[$column], $value.Length)
        }
        $row
    }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add((($columns | ForEach-Object { $_.PadRight($widths[$_]) }) -join '  '))
    $lines.Add((($columns | ForEach-Object { '-' * $widths[$_] }) -join '  '))
    foreach ($row in $rows) { $lines.Add((($columns | ForEach-Object { $row[$_].PadRight($widths[$_]) }) -join '  ')) }
    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

function ConvertTo-BHOutput {
    [CmdletBinding()]
    param(
        [object[]]$Logs,
        [ValidateSet('table', 'json', 'jsonl', 'csv')][string]$Format = 'table'
    )
    switch ($Format) {
        'json' { return (ConvertTo-Json -InputObject @($Logs) -Depth 50) + [Environment]::NewLine }
        'jsonl' {
            if (@($Logs).Count -eq 0) { return '' }
            return (($Logs | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 50 }) -join [Environment]::NewLine) + [Environment]::NewLine
        }
        'csv' { return ConvertTo-BHCsv -Logs $Logs }
        default { return ConvertTo-BHTable -Logs $Logs }
    }
}

function Write-BHOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        [Console]::Out.Write($Content)
        return
    }
    $fullPath = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    if (-not [IO.Directory]::Exists($parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($fullPath, $Content, $utf8NoBom)
}

function Invoke-BHStreamExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('jsonl', 'csv')][string]$Format,
        [Parameter(Mandatory)][scriptblock]$Fetch
    )
    $fullPath = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    $parent = [IO.Path]::GetDirectoryName($fullPath)
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporaryPath = Join-Path $parent ('.{0}.{1}.tmp' -f [IO.Path]::GetFileName($fullPath), [guid]::NewGuid().ToString('N'))
    $writer = $null
    try {
        $writer = New-Object IO.StreamWriter($temporaryPath, $false, (New-Object Text.UTF8Encoding($false)))
        if ($Format -eq 'csv') { $writer.Write((ConvertTo-BHCsv -Logs @())) }
        $sink = {
            param($Record)
            if ($Format -eq 'csv') {
                $csv = ConvertTo-BHCsv -Logs @($Record)
                $writer.Write($csv.Substring($csv.IndexOf([Environment]::NewLine) + [Environment]::NewLine.Length))
            }
            else { $writer.WriteLine(($Record | ConvertTo-Json -Compress -Depth 50)) }
        }
        $result = & $Fetch -RecordSink $sink
        $writer.Dispose()
        $writer = $null
        if ([IO.File]::Exists($fullPath)) { [IO.File]::Replace($temporaryPath, $fullPath, [NullString]::Value) }
        else { [IO.File]::Move($temporaryPath, $fullPath) }
        return $result
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Read-BHConfig {
    [CmdletBinding()]
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot 'Get-BHAuditLogs.config.json'
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{} }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Config file not found: $Path" }
    try { return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json }
    catch { throw "Could not read config file: $($_.Exception.Message)" }
}

function Get-BHFirstValue {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Values)
    foreach ($value in $Values) {
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) { return $value }
    }
    return $null
}

function ConvertFrom-BHEnvironmentBoolean {
    param([string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    switch ($value.Trim().ToLowerInvariant()) {
        { $_ -in @('1', 'true', 'yes', 'on') } { return $true }
        { $_ -in @('0', 'false', 'no', 'off') } { return $false }
        default { throw "$Name must be true or false." }
    }
}

function Read-BHSecret {
    param([Parameter(Mandatory)][string]$Prompt)
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-BHAuditLogsMain {
    [CmdletBinding()]
    param([hashtable]$Arguments, [switch]$PrepareOnly, [switch]$Resolved)
    $cfg = if ($Resolved) { [pscustomobject]@{} } else { Read-BHConfig -Path ([string]$Arguments.Config) }
    $environment = if ($Resolved) { @{} } else { @{ Url=$env:BH_URL; TokenId=$env:BH_TOKEN_ID; TokenKey=$env:BH_TOKEN_KEY; BearerToken=$env:BH_BEARER_TOKEN; Timeout=$env:BH_TIMEOUT } }
    $baseUrl = Get-BHFirstValue $Arguments.Url $environment.Url $cfg.url $cfg.bh_url
    if ([string]::IsNullOrWhiteSpace([string]$baseUrl) -and -not $Arguments.NoPrompt) { $baseUrl = Read-Host 'BloodHound URL' }
    if ([string]::IsNullOrWhiteSpace([string]$baseUrl)) { throw 'BloodHound URL is required (-Url, BH_URL, config, or prompt).' }
    $parsedUrl = $null
    if (-not [uri]::TryCreate([string]$baseUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or $parsedUrl.Scheme -notin @('http', 'https')) {
        throw 'BloodHound URL must be an absolute http:// or https:// URL.'
    }

    $tokenIdValue = Get-BHFirstValue $Arguments.TokenId $environment.TokenId $cfg.token_id
    $tokenKeyValue = Get-BHFirstValue $Arguments.TokenKey $environment.TokenKey $cfg.token_key
    $bearerValue = Get-BHFirstValue $Arguments.BearerToken $environment.BearerToken $cfg.bearer_token
    if (-not ($tokenIdValue -or $tokenKeyValue -or $bearerValue) -and -not $Arguments.NoPrompt) {
        $method = (Read-Host 'Authentication method [signed/bearer] (signed)').Trim().ToLowerInvariant()
        if (-not $method) { $method = 'signed' }
        switch ($method) {
            'signed' { $tokenIdValue = Read-Host 'BloodHound token ID'; $tokenKeyValue = Read-BHSecret 'BloodHound token key' }
            'bearer' { $bearerValue = Read-BHSecret 'BloodHound bearer JWT' }
            default { throw 'Authentication method must be signed or bearer.' }
        }
    }

    $timeoutValue = [int](Get-BHFirstValue $Arguments.Timeout $environment.Timeout $cfg.timeout_seconds 30)
    $maxRetriesValue = [int](Get-BHFirstValue $Arguments.MaxRetries $cfg.max_retries 3)
    $retryDelayValue = [double](Get-BHFirstValue $Arguments.RetryDelay $cfg.retry_delay_seconds 1)
    if ($timeoutValue -le 0 -or $maxRetriesValue -lt 0 -or $retryDelayValue -lt 0) {
        throw 'Timeout must be positive; retry values cannot be negative.'
    }
    $verifyEnv = if ($Resolved) { $null } else { ConvertFrom-BHEnvironmentBoolean BH_VERIFY_SSL }
    $verifySsl = Get-BHFirstValue $verifyEnv $cfg.verify_ssl $true
    $skipTls = [bool]$Arguments.SkipCertificateCheck -or -not [Convert]::ToBoolean($verifySsl)

    $authGroups = [int][bool]$bearerValue + [int][bool]($tokenIdValue -or $tokenKeyValue)
    if ($authGroups -gt 1) { throw 'Multiple authentication methods were populated. Clear stale parameters, BH_* variables, or config values.' }
    if ([bool]$tokenIdValue -ne [bool]$tokenKeyValue) { throw 'Signed authentication requires both token ID and token key.' }
    elseif (-not $bearerValue -and -not ($tokenIdValue -and $tokenKeyValue)) { throw 'No complete authentication method was provided.' }

    $defaultDays = [double](Get-BHFirstValue $Arguments.DefaultDays $cfg.default_days $cfg.default_time_range_days 7)
    $range = Resolve-BHTimeRange -Days $Arguments.Days -Hours $Arguments.Hours -Start $Arguments.Start -End $Arguments.End -DefaultDays $defaultDays
    $filters = @{
        actor_id = $Arguments.ActorId; actor_name = $Arguments.ActorName; actor_email = $Arguments.ActorEmail
        action = $Arguments.Action; request_id = $Arguments.RequestId; source = $Arguments.Source; status = $Arguments.Status
    }
    $baseQuery = New-BHBaseQuery -After $range.After -Before $range.Before -Filters $filters
    $pageSizeValue = [int](Get-BHFirstValue $Arguments.PageSize $cfg.page_size $cfg.batch_size 500)
    $formatValue = [string](Get-BHFirstValue $Arguments.OutputFormat $cfg.output_format 'table')
    if ($formatValue -notin @('table', 'json', 'jsonl', 'csv')) { throw 'output_format must be table, json, jsonl, or csv.' }
    $apiPath = $script:BHApiPath
    # A closure runs in a dynamic module, which cannot resolve private script
    # functions by name during normal (non-dot-sourced) invocation. Capture the
    # function's scriptblock to retain its original session state and helpers.
    $requestInvoker = ${function:Invoke-BHJsonRequest}
    $requestPage = {
        param($QueryPairs)
        & $requestInvoker -Method GET -BaseUrl $baseUrl -Path $apiPath -QueryPairs $QueryPairs -BearerToken $bearerValue -TokenId $tokenIdValue -TokenKey $tokenKeyValue -TimeoutSeconds $timeoutValue -MaxRetries $maxRetriesValue -RetryDelaySeconds $retryDelayValue -SkipCertificateCheck:$skipTls
    }.GetNewClosure()
    if ($pageSizeValue -le 0 -or [int]$Arguments.MaxRecords -lt 0) { throw 'Page size must be positive; maximum records cannot be negative.' }
    if ($PrepareOnly) {
        return [pscustomobject]@{ Url = $baseUrl; Range = $range; Query = $baseQuery; PageSize = $pageSizeValue; Format = $formatValue; RequestPage = $requestPage; SkipTls = $skipTls; Timeout = $timeoutValue; MaxRetries = $maxRetriesValue; RetryDelay = $retryDelayValue }
    }
    $fetch = {
        param($RecordSink)
        Get-BHAuditLogPages -RequestPage $requestPage -BaseQuery $baseQuery -PageSize $pageSizeValue -MaxRecords $Arguments.MaxRecords -Search $Arguments.Search -Status $Arguments.Status -RecordSink $RecordSink
    }
    if ($Arguments.OutputFile -and $formatValue -in @('jsonl', 'csv')) {
        $result = Invoke-BHStreamExport -Path $Arguments.OutputFile -Format $formatValue -Fetch $fetch
    }
    else {
        $result = & $fetch
        $content = ConvertTo-BHOutput -Logs $result.Logs -Format $formatValue
        Write-BHOutput -Content $content -Path $Arguments.OutputFile
    }
    if (-not $Arguments.NoSummary) {
        $destination = if ($Arguments.OutputFile) { $Arguments.OutputFile } else { 'stdout' }
        [Console]::Error.WriteLine(('Retrieved {0} audit record(s); {1} matched; output: {2}' -f $result.Fetched, $result.MatchedCount, $destination))
    }
}

function Read-BHMenu {
    param([string]$Prompt, [switch]$Secret, [switch]$HideNavigation)
    if (-not $Secret -and $Prompt.StartsWith('[1]')) {
        foreach ($option in [regex]::Split($Prompt, ' (?=\[\d+\])')) { Write-Host $option }
        Write-Host '[R] Return to main menu'
        Write-Host '[Q] Quit'
        $Prompt = 'Select an option'
        $HideNavigation = $true
    }
    $label = $Prompt + $(if ($HideNavigation) { '' } else { ' [R: main menu, Q: quit]' })
    $value = if ($Secret) { Read-BHSecret -Prompt $label } else { Read-Host $label }
    if ($null -eq $value) { throw 'BH_MENU_QUIT' }
    $value = $value.Trim()
    if ($value -ieq 'r') { throw 'BH_MENU_RETURN' }
    if ($value -ieq 'q') { throw 'BH_MENU_QUIT' }
    return $value
}

function Read-BHMenuNumber {
    param([string]$Prompt, [switch]$Integer, [double]$Minimum = 0)
    $text = Read-BHMenu $Prompt
    $number = 0.0
    if (-not [double]::TryParse($text, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -or [double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt $Minimum) {
        throw "Enter a finite number of at least $Minimum."
    }
    if ($Integer) {
        if ($number -ne [Math]::Truncate($number) -or $number -gt [int]::MaxValue) { throw 'Enter a whole number within the supported integer range.' }
        return [int]$number
    }
    return $number
}

function Get-BHInteractiveDefaults {
    param([hashtable]$Arguments, $Config)
    $state = $Arguments.Clone()
    $mapping = @(
        @('Url', 'BH_URL', 'url', 'bh_url', $null),
        @('TokenId', 'BH_TOKEN_ID', 'token_id', '', $null),
        @('TokenKey', 'BH_TOKEN_KEY', 'token_key', '', $null),
        @('BearerToken', 'BH_BEARER_TOKEN', 'bearer_token', '', $null),
        @('Timeout', 'BH_TIMEOUT', 'timeout_seconds', '', 30),
        @('MaxRetries', '', 'max_retries', '', 3),
        @('RetryDelay', '', 'retry_delay_seconds', '', 1),
        @('PageSize', '', 'page_size', 'batch_size', 500),
        @('OutputFormat', '', 'output_format', '', 'table')
    )
    foreach ($item in $mapping) {
        $envValue = if ($item[1]) { [Environment]::GetEnvironmentVariable($item[1]) } else { $null }
        $fallback = if ($item[3]) { $Config.($item[3]) } else { $null }
        $state[$item[0]] = Get-BHFirstValue $Arguments[$item[0]] $envValue $Config.($item[2]) $fallback $item[4]
    }
    $verify = Get-BHFirstValue (ConvertFrom-BHEnvironmentBoolean BH_VERIFY_SSL) $Config.verify_ssl $true
    if ($verify -isnot [bool]) { throw 'verify_ssl in JSON config must be true or false.' }
    $state.SkipCertificateCheck = [bool]$Arguments.SkipCertificateCheck -or -not $verify
    $state.NoPrompt = $true
    $state.Interactive = $false
    $state.MaxRecords = [int]$Arguments.MaxRecords
    if ($null -eq $state.Days -and $null -eq $state.Hours -and -not $state.Start -and -not $state.End) {
        $state.Days = [double](Get-BHFirstValue $Config.default_days $Config.default_time_range_days 7)
    }
    return $state
}

function Get-BHInteractivePrepared {
    param([hashtable]$State)
    $parsed = $null
    if ([uri]::TryCreate([string]$State.Url, [UriKind]::Absolute, [ref]$parsed)) {
        if ($parsed.UserInfo -or $parsed.Query -or $parsed.Fragment) { throw 'Use a base URL without embedded credentials, query, or fragment.' }
    }
    return Invoke-BHAuditLogsMain -Arguments $State -PrepareOnly -Resolved
}

function Get-BHEquivalentCommand {
    param([hashtable]$State, $Prepared)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $parts.Add('.\powershell\Get-BHAuditLogs.ps1')
    $values = [ordered]@{ Url=$State.Url; Start=(ConvertTo-BHRfc3339 $Prepared.Range.After); End=(ConvertTo-BHRfc3339 $Prepared.Range.Before) }
    foreach ($name in @('ActorId','ActorName','ActorEmail','Action','RequestId','Source','Status','Search','PageSize','MaxRecords','Timeout','MaxRetries','RetryDelay','OutputFormat','OutputFile')) {
        if ($null -ne $State[$name] -and [string]$State[$name] -ne '') { $values[$name] = $State[$name] }
    }
    foreach ($name in $values.Keys) {
        $parts.Add('-' + $name)
        $parts.Add("'" + ([string]$values[$name]).Replace("'", "''") + "'")
    }
    if ($State.SkipCertificateCheck) { $parts.Add('-SkipCertificateCheck') }
    if ($State.Verbose) { $parts.Add('-Verbose') }
    $parts.Add('-NoPrompt')
    return $parts -join ' '
}

function Show-BHInteractiveReview {
    param([hashtable]$State, $Prepared)
    $method = if ($State.BearerToken) { 'bearer [hidden]' } else { 'signed token [hidden]' }
    Write-Host "`nConnection: $($State.Url); authentication: $method"
    Write-Host ('UTC boundaries (exclusive): after {0}; before {1}' -f (ConvertTo-BHRfc3339 $Prepared.Range.After), (ConvertTo-BHRfc3339 $Prepared.Range.Before))
    $filterText = @('ActorId','ActorName','ActorEmail','Action','RequestId','Source','Status','Search') | Where-Object { $State[$_] } | ForEach-Object { "$_=$($State[$_])" }
    Write-Host ('Filters: ' + $(if ($filterText) { $filterText -join ', ' } else { 'none' }))
    Write-Host "Output: $($State.OutputFormat); destination: $(if ($State.OutputFile) { $State.OutputFile } else { 'console preview' })"
    Write-Host "Maximum records inspected BEFORE search: $(if ($State.MaxRecords) { $State.MaxRecords } else { 'all' }); page size: $($Prepared.PageSize)"
    Write-Host "Timeout: $($Prepared.Timeout)s; retries: $($Prepared.MaxRetries); delay: $($Prepared.RetryDelay)s; TLS verification: $(if ($Prepared.SkipTls) { 'OFF' } else { 'ON' }); verbose: $([bool]$State.Verbose)"
    Write-Host 'Equivalent PowerShell command (credentials omitted; set BH_* authentication variables):'
    Write-Host (Get-BHEquivalentCommand -State $State -Prepared $Prepared)
}

function Export-BHCachedResults {
    param([string]$Cache, [string]$Format, [string]$Destination)
    if ($Format -notin @('table','json','jsonl','csv')) { throw 'Choose table, json, jsonl, or csv.' }
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'Enter an output file path.' }
    if (Test-Path -LiteralPath $Destination) {
        if ((Read-BHMenu "Replace existing file $Destination? Type YES") -ine 'YES') {
            Write-Host 'Export cancelled; existing file preserved.'
            return
        }
    }
    $fetch = {
        param($RecordSink)
        $count = 0
        $reader = [IO.File]::OpenText($Cache)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                & $RecordSink ($line | ConvertFrom-Json) | Out-Null
                $count++
            }
        }
        finally { $reader.Dispose() }
        [pscustomobject]@{ Fetched=$count; MatchedCount=$count; Logs=@() }
    }
    if ($Format -in @('jsonl','csv')) { Invoke-BHStreamExport -Path $Destination -Format $Format -Fetch $fetch | Out-Null }
    else {
        $records = @([IO.File]::ReadAllLines($Cache) | ForEach-Object { $_ | ConvertFrom-Json })
        Write-BHOutput -Path $Destination -Content (ConvertTo-BHOutput -Logs $records -Format $Format)
    }
    Write-Host "Exported cached results to $Destination; no new API request."
}

function Show-BHInteractiveResults {
    param([string]$Cache, $Result, [int]$MaxRecords)
    Write-Host "`nRetrieved $($Result.Fetched); matched $($Result.MatchedCount)."
    if ($MaxRecords -and $Result.Fetched -ge $MaxRecords) { Write-Host 'Record limit reached; results may be partial.' }
    $preview = New-Object 'System.Collections.Generic.List[string]'
    $reader = [IO.File]::OpenText($Cache)
    try {
        while ($preview.Count -lt 50 -and $null -ne ($line = $reader.ReadLine())) { $preview.Add($line) }
    }
    finally { $reader.Dispose() }
    Write-Host "Showing first $($preview.Count) of $($Result.MatchedCount) matches:"
    if ($preview.Count -gt 0) {
        $records = @($preview | ForEach-Object { $_ | ConvertFrom-Json })
        $lines = (ConvertTo-BHTable -Logs $records).TrimEnd("`r", "`n") -split [Environment]::NewLine
        Write-Host ('No.'.PadRight(4) + ' ' + $lines[0])
        Write-Host ('---- ' + $lines[1])
        for ($index = 2; $index -lt $lines.Count; $index++) {
            Write-Host (('[{0}]' -f ($index - 1)).PadRight(4) + ' ' + $lines[$index])
        }
    }
    else { Write-Host 'No audit logs matched.' }
    while ($true) {
        try {
            Write-Host ''
            $choice = Read-BHMenu '[1] Full event JSON [2] Export current results [3] Edit query [4] Review and rerun'
            switch ($choice) {
                '1' {
                    $number = Read-BHMenuNumber "Event number (1-$($Result.MatchedCount); includes matches beyond preview)" -Integer -Minimum 1
                    if ($number -gt $Result.MatchedCount) { throw 'Event number is outside the current results.' }
                    $index = 0
                    $reader = [IO.File]::OpenText($Cache)
                    try {
                        while ($null -ne ($line = $reader.ReadLine())) {
                            if (++$index -eq $number) { Write-Host ($line | ConvertFrom-Json | ConvertTo-Json -Depth 50); break }
                        }
                    }
                    finally { $reader.Dispose() }
                }
                '2' {
                    $format = (Read-BHMenu 'Format: table/json/jsonl/csv').ToLowerInvariant()
                    $destination = Read-BHMenu 'Output file path'
                    Export-BHCachedResults -Cache $Cache -Format $format -Destination $destination
                }
                { $_ -in @('3','4') } { return $choice }
                default { Write-Host 'Choose 1-4, R, or Q.' }
            }
        }
        catch {
            if ($_.Exception.Message -in @('BH_MENU_RETURN','BH_MENU_QUIT')) { throw }
            Write-Host "Error: $($_.Exception.Message)"
        }
    }
}

function Invoke-BHInteractive {
    param([hashtable]$Arguments)
    $state = Get-BHInteractiveDefaults -Arguments $Arguments -Config (Read-BHConfig -Path $Arguments.Config)
    Write-Host @'
 ____  _   _    _             _ _ _   _
| __ )| | | |  / \  _   _  __| (_) |_| |    ___   __ _ ___
|  _ \| |_| | / _ \| | | |/ _` | | __| |   / _ \ / _` / __|
| |_) |  _  |/ ___ \ |_| | (_| | | |_| |__| (_) | (_| \__ \
|____/|_| |_/_/   \_\__,_|\__,_|_|\__|_____\___/ \__, |___/
                                                |___/
'@ -ForegroundColor Cyan
    $filters = @('ActorId','ActorName','ActorEmail','Action','RequestId','Source','Status','Search')
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('bh-audit-session-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $cache = $null
    $result = $null
    $resultMaxRecords = 0
    try {
        while ($true) {
            try {
                $hostName = 'not configured'
                $parsed = $null
                if ([uri]::TryCreate([string]$state.Url, [UriKind]::Absolute, [ref]$parsed)) { $hostName = $parsed.Host }
                Write-Host "`nBloodHound Audit Logs | host: $hostName | output: $($state.OutputFormat) | maximum inspected: $(if ($state.MaxRecords) { $state.MaxRecords } else { 'all' })"
                $filterText = $filters | Where-Object { $state[$_] } | ForEach-Object { "$_=$($state[$_])" }
                Write-Host ('Current filters: ' + $(if ($filterText) { $filterText -join ', ' } else { 'none' }))
                Write-Host ('Time: ' + $(if ($state.Start -or $state.End) { "$($state.Start) to $($state.End)" } elseif ($null -ne $state.Hours) { "last $($state.Hours) hours" } else { "last $($state.Days) days" }))
                foreach ($option in @('[1] Connection/authentication', '[2] Quick investigations', '[3] Custom query', '[4] Output', '[5] Advanced', '[6] Review/run', '[7] Current results', '[R] Return to main menu', '[Q] Quit')) {
                    Write-Host $option
                }
                $choice = Read-BHMenu 'Select an option' -HideNavigation
                $draft = $state.Clone()
                switch ($choice) {
                    '1' {
                        $awaitingAuth = $false
                        while ($true) {
                            $draft = $state.Clone()
                            $action = Read-BHMenu '[1] Load JSON config [2] Set URL [3] Signed token [4] Bearer JWT [5] Test audit access'
                            switch ($action) {
                                '1' {
                                    $path = Read-BHMenu 'Config path'
                                    if (-not $path) { throw 'Enter a config path.' }
                                    $draft = Get-BHInteractiveDefaults -Arguments @{} -Config (Read-BHConfig -Path $path)
                                    foreach ($name in ($filters + @('Days','Hours','Start','End','MaxRecords','OutputFile'))) { $draft[$name] = $state[$name] }
                                    Write-Host 'Config loaded (environment values take precedence); credentials hidden.'
                                }
                                '2' { $draft.Url = Read-BHMenu 'Base URL, e.g. http://localhost:8080' }
                                '3' {
                                    $draft.TokenId = Read-BHMenu 'Token ID' -Secret
                                    $draft.TokenKey = Read-BHMenu 'Token key' -Secret
                                    $draft.BearerToken = $null
                                }
                                '4' {
                                    $draft.BearerToken = Read-BHMenu 'Bearer JWT' -Secret
                                    $draft.TokenId = $draft.TokenKey = $null
                                }
                                '5' {
                                    $prepared = Get-BHInteractivePrepared -State $state
                                    Get-BHAuditLogPages -RequestPage $prepared.RequestPage -BaseQuery (New-BHBaseQuery -After $prepared.Range.After -Before $prepared.Range.Before) -PageSize 1 -MaxRecords 1 | Out-Null
                                    Write-Host 'Audit access succeeded (an empty result is valid).'
                                }
                                default { throw 'Choose 1-5.' }
                            }
                            $state = $draft
                            $awaitingAuth = $awaitingAuth -or $action -eq '2'
                            $signed = $draft.TokenId -and $draft.TokenKey -and -not $draft.BearerToken
                            $bearer = $draft.BearerToken -and -not ($draft.TokenId -or $draft.TokenKey)
                            if (-not $awaitingAuth -or $signed -or $bearer) { break }
                            Write-Host 'URL saved. Configure a complete signed token or bearer JWT to finish connection setup, or use R to return.'
                        }
                    }
                    '2' {
                        $action = Read-BHMenu '[1] Recent activity [2] Failed logins [3] Actor [4] Action [5] Request ID [6] Search nested details'
                        if ($action -notin @('1','2','3','4','5','6')) { throw 'Choose 1-6.' }
                        foreach ($name in $filters) { $draft[$name] = $null }
                        $draft.Days = $draft.Start = $draft.End = $null
                        $draft.Hours = 24
                        switch ($action) {
                            '2' { $draft.Action = 'LoginAttempt'; $draft.Status = 'failure' }
                            '3' {
                                $field = Read-BHMenu 'Actor field: id/name/email'
                                if ($field -notin @('id','name','email')) { throw 'Choose id, name, or email.' }
                                $draft['Actor' + $field] = Read-BHMenu 'Exact actor value'
                            }
                            { $_ -in @('4','5','6') } {
                                $name = @{ '4'='Action'; '5'='RequestId'; '6'='Search' }[$action]
                                $draft[$name] = Read-BHMenu "$name value"
                            }
                        }
                        Write-Host 'Preset selects the last 24 hours and replaces previous filters. Matching events do not prove a completed change.'
                    }
                    '3' {
                        Write-Host 'Actor/action/request/source filters are exact server filters. Search is a client-side substring across all fields; intent status is also client-side.'
                        $action = Read-BHMenu '[1] Time range [2] Edit filter [3] Clear all filters'
                        switch ($action) {
                            '1' {
                                $mode = Read-BHMenu '[1] Last hour [2] 12 hours [3] 24 hours [4] 7 days [5] 30 days [6] Custom hours [7] Custom days [8] Absolute UTC dates'
                                $draft.Days = $draft.Hours = $draft.Start = $draft.End = $null
                                if ($mode -in @('1','2','3','4','5')) { $draft.Hours = @{ '1'=1; '2'=12; '3'=24; '4'=168; '5'=720 }[$mode] }
                                elseif ($mode -in @('6','7')) {
                                    $name = if ($mode -eq '6') { 'Hours' } else { 'Days' }
                                    $draft[$name] = Read-BHMenuNumber 'Positive duration' -Minimum 0.000001
                                }
                                elseif ($mode -eq '8') {
                                    $draft.Start = Read-BHMenu 'UTC start date/time'
                                    $draft.End = Read-BHMenu 'UTC end date/time (date-only includes entire day)'
                                    Resolve-BHTimeRange -Start $draft.Start -End $draft.End | Out-Null
                                }
                                else { throw 'Choose 1-8.' }
                            }
                            '2' {
                                $field = Read-BHMenu ('Filter: ' + ($filters -join '/'))
                                if ($field -notin $filters) { throw 'Unknown filter.' }
                                $value = Read-BHMenu "$field`: enter value, or '-' to clear"
                                if ($value -eq '-') { $value = $null }
                                if ($field -ieq 'Status' -and $null -ne $value -and $value -notin @('intent','success','failure')) { throw 'Status must be intent, success, or failure.' }
                                if ($field -notin @('Search','Status')) { ConvertTo-BHExactFilter -Name $field -Value $value | Out-Null }
                                $draft[$field] = $value
                            }
                            '3' { foreach ($name in $filters) { $draft[$name] = $null } }
                            default { throw 'Choose 1-3.' }
                        }
                    }
                    '4' {
                        $draft.OutputFormat = (Read-BHMenu 'Output format: table/json/jsonl/csv').ToLowerInvariant()
                        if ($draft.OutputFormat -notin @('table','json','jsonl','csv')) { throw 'Unknown output format.' }
                        $draft.OutputFile = Read-BHMenu "Destination path, or '-' for console preview"
                        if ($draft.OutputFile -eq '-') { $draft.OutputFile = $null }
                        Write-Host 'JSONL/CSV files stream to disk; JSON/table exports buffer records. Console preview shows at most 50 numbered events.'
                    }
                    '5' {
                        $action = Read-BHMenu '[1] Page size [2] Maximum records inspected [3] Timeout [4] Retry count [5] Retry delay [6] Verbose [7] TLS verification'
                        $settings = @{ '1'=@('PageSize',1); '2'=@('MaxRecords',0); '3'=@('Timeout',1); '4'=@('MaxRetries',0); '5'=@('RetryDelay',0) }
                        if ($settings.ContainsKey($action)) {
                            $name, $minimum = $settings[$action]
                            $label = $name + $(if ($name -eq 'MaxRecords') { ' (0 means all, before search)' } else { '' })
                            $draft[$name] = Read-BHMenuNumber $label -Minimum $minimum -Integer:($action -ne '5')
                        }
                        elseif ($action -in @('6','7')) {
                            $label = if ($action -eq '6') { 'Enable verbose? yes/no' } else { 'Validate TLS certificates? yes/no' }
                            $value = Read-BHMenu $label
                            if ($value -notin @('yes','no')) { throw 'Choose yes or no.' }
                            if ($action -eq '6') { $draft.Verbose = $value -ieq 'yes' }
                            else { $draft.SkipCertificateCheck = $value -ieq 'no' }
                        }
                        else { throw 'Choose 1-7.' }
                    }
                    { $_ -in @('6','7') } {
                        $rerun = $choice -eq '6'
                        if (-not $rerun -and -not $cache) { throw 'Run an investigation first.' }
                        while ($true) {
                            if ($rerun) {
                                $prepared = Get-BHInteractivePrepared -State $state
                                Show-BHInteractiveReview -State $state -Prepared $prepared
                                if ((Read-BHMenu 'Run this query? yes/no') -ine 'yes') { break }
                                $target = Join-Path $directory ([guid]::NewGuid().ToString('N') + '.jsonl')
                                $fetch = {
                                    param($RecordSink)
                                    Get-BHAuditLogPages -RequestPage $prepared.RequestPage -BaseQuery $prepared.Query -PageSize $prepared.PageSize -MaxRecords $state.MaxRecords -Search $state.Search -Status $state.Status -RecordSink $RecordSink -Verbose:([bool]$state.Verbose)
                                }
                                $newResult = Invoke-BHStreamExport -Path $target -Format jsonl -Fetch $fetch
                                if ($cache -and [IO.File]::Exists($cache)) { [IO.File]::Delete($cache) }
                                $cache = $target
                                $result = $newResult
                                $resultMaxRecords = $state.MaxRecords
                                if ($state.OutputFile) { Export-BHCachedResults -Cache $cache -Format $state.OutputFormat -Destination $state.OutputFile }
                            }
                            $rerun = (Show-BHInteractiveResults -Cache $cache -Result $result -MaxRecords $resultMaxRecords) -eq '4'
                            if (-not $rerun) { break }
                        }
                    }
                    default { throw 'Choose 1-7, R, or Q.' }
                }
                $state = $draft
            }
            catch {
                if ($_.Exception.Message -eq 'BH_MENU_QUIT') { Write-Host 'Interactive session ended.'; return }
                if ($_.Exception.Message -eq 'BH_MENU_RETURN') { continue }
                Write-Host "Error: $($_.Exception.Message)"
            }
        }
    }
    finally {
        # This directory was uniquely allocated above; delete only its cache files.
        foreach ($file in [IO.Directory]::GetFiles($directory)) { [IO.File]::Delete($file) }
        [IO.Directory]::Delete($directory)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($Interactive) {
            if ($NoPrompt) { throw '-Interactive cannot be combined with -NoPrompt.' }
            Invoke-BHInteractive -Arguments $PSBoundParameters
        }
        else { Invoke-BHAuditLogsMain -Arguments $PSBoundParameters }
    }
    catch {
        [Console]::Error.WriteLine("Error: $($_.Exception.Message)")
        exit 1
    }
}
