<#
.SYNOPSIS
    vulnagent-local AI agent scan for Windows: finds the AI agents, AI coding
    tools, local AI servers and MCP servers on the machine, and the risks they
    bring, and writes the reports on this machine. Nothing is sent to a server.

.DESCRIPTION
    install-local.ps1 sets this up as the nightly "vulnagent-local-ai"
    scheduled task (runs as SYSTEM). Each run looks in every user profile and
    machine-wide for:

      * AI coding agents (Claude Code, Codex CLI, Gemini CLI, GitHub Copilot
        CLI, Aider, ...), AI code editors (Cursor, Windsurf, Kiro, ...) and
        agent extensions (GitHub Copilot, Cline, Roo Code, Continue, ...),
      * AI assistant apps (Claude, ChatGPT, Microsoft Copilot, ...),
      * local AI servers (Ollama, LM Studio, Jan, GPT4All, llama.cpp, Open
        WebUI, LiteLLM, ...) and agent frameworks in Python (LangChain, CrewAI,
        AutoGen, ...),
      * the MCP servers configured for these tools,

    and reports:

      * local AI servers that other machines can reach, or that run as SYSTEM,
      * API keys and tokens stored in plain text in AI agent and MCP configs
        (the report shows only the first characters),
      * agents set to run commands without asking (Claude Code
        bypassPermissions, Codex approval_policy "never", ...),
      * known vulnerabilities of the installed versions, from OSV.dev,
      * MCP servers that start an unpinned package or use plain HTTP,
      * AI agents your policy doesn't allow (ai_allowed, ai_blocked),
      * every AI agent and MCP server found, as Info (an inventory),

    compares the findings with the previous run, and writes the reports to
    C:\vulnagent-local\reports: ai.html (open in a browser), ai.json
    (all data), ai-findings.json, a dated copy in reports\history and
    index.html, which lists all reports.

    It only reads files, the registry and the process list: it runs nothing it
    finds and changes nothing. The only network access is to OSV.dev (package
    names and versions only). Needs only Windows PowerShell 5.1.

    Exit codes: 0 done, 2 part of the scan failed (the report may be
    incomplete), 3 failed (no report written).

.EXAMPLE
    vulnagent-local-ai.ps1
    Scan and write the reports, using C:\vulnagent-local\config.json.

.EXAMPLE
    vulnagent-local-ai.ps1 -Html $env:TEMP\ai-agents.html
    Also write the HTML report where your browser can open it without
    administrator rights.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$Output,
    [string]$Html
)
$ErrorActionPreference = 'Stop'
$VERSION = '1.0.0'
$SCAN_TYPE = 'Generic Findings Import'
$OSV_QUERY_URL = 'https://api.osv.dev/v1/query'
$DataDir = Join-Path "$env:SystemDrive\" 'vulnagent-local'   # C:\vulnagent-local
if (-not $ConfigPath) { $ConfigPath = Join-Path $DataDir 'config.json' }
$LogFile = Join-Path $DataDir 'ai-agents.log'

$DefaultConfig = [ordered]@{
    ai_inventory           = $true              # list every AI agent and MCP server found, as Info
    ai_osv                 = $true              # look up known vulnerabilities on OSV.dev
    ai_allowed             = @()                # when set, AI agents not named here are reported (wildcards allowed)
    ai_blocked             = @()                # AI agents that are not allowed at all (wildcards allowed)
    ai_unapproved_severity = 'Medium'           # severity of an agent missing from ai_allowed
    ai_ignore              = @()                # agent names, finding IDs or unique IDs to leave out (wildcards allowed)
    keep_reports_days      = 90                 # dated copies in reports\history; 0 keeps them all
}

$SeverityOrder = [ordered]@{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$FindingKinds = [ordered]@{
    exposed = 'Network'; service = 'Service'; secret = 'Secret'; setting = 'Setting'; vulnerability = 'Vulnerability'
    policy = 'Policy'; mcp = 'MCP server'; inventory = 'Inventory'
}
$AiKinds = [ordered]@{
    cli = 'AI coding agent'; ide = 'AI code editor'; ext = 'Editor extension'; desktop = 'AI assistant app'
    server = 'Local AI server'; framework = 'Agent framework (Python)'
}

# What is looked for. app: files, where L = the user's AppData\Local, R = AppData\Roaming,
# H = the user's profile folder, P = Program Files (both), M = the machine's application data
# folder for all users, A = an absolute path.
# npm: global npm packages. ext: VS Code (and Cursor, Windsurf, ...) extension IDs.
# py: Python packages. appx: Store app names. proc: process names of local AI servers,
# cmd: a regex for their command line. appOsv: OSV.dev package for the app's version.
# port: the server's default port.
$AiCatalog = @(
    # AI coding agents
    @{ name = 'Claude Code'; kind = 'cli'; vendor = 'Anthropic'; npm = @('@anthropic-ai/claude-code'); ext = @('anthropic.claude-code')
       app = @('H:.local\bin\claude.exe'); versions = 'H:.local\share\claude\versions'; appOsv = @('npm', '@anthropic-ai/claude-code') }
    @{ name = 'Codex CLI'; kind = 'cli'; vendor = 'OpenAI'; npm = @('@openai/codex'); ext = @('openai.chatgpt') }
    @{ name = 'Gemini CLI'; kind = 'cli'; vendor = 'Google'; npm = @('@google/gemini-cli') }
    @{ name = 'GitHub Copilot CLI'; kind = 'cli'; vendor = 'GitHub'; npm = @('@github/copilot') }
    @{ name = 'Qwen Code'; kind = 'cli'; vendor = 'Alibaba'; npm = @('@qwen-code/qwen-code') }
    @{ name = 'OpenCode'; kind = 'cli'; vendor = 'SST'; npm = @('opencode-ai') }
    @{ name = 'Amp'; kind = 'cli'; vendor = 'Sourcegraph'; npm = @('@sourcegraph/amp'); ext = @('sourcegraph.amp') }
    @{ name = 'Augment'; kind = 'cli'; vendor = 'Augment Code'; npm = @('@augmentcode/auggie'); ext = @('augment.vscode-augment') }
    @{ name = 'Cline'; kind = 'ext'; vendor = 'Cline'; npm = @('cline'); ext = @('saoudrizwan.claude-dev') }
    @{ name = 'Aider'; kind = 'cli'; vendor = 'Aider'; py = @('aider-chat') }
    @{ name = 'Open Interpreter'; kind = 'cli'; vendor = 'Open Interpreter'; py = @('open-interpreter') }
    @{ name = 'OpenHands'; kind = 'cli'; vendor = 'All Hands AI'; py = @('openhands-ai') }
    @{ name = 'Goose'; kind = 'cli'; vendor = 'Block'; app = @('L:Programs\Goose\Goose.exe', 'H:.local\bin\goose.exe') }
    # AI code editors
    @{ name = 'Cursor'; kind = 'ide'; vendor = 'Anysphere'; app = @('L:Programs\cursor\Cursor.exe', 'P:cursor\Cursor.exe'); uninstall = '^Cursor( \(User\))?$' }
    @{ name = 'Windsurf'; kind = 'ide'; vendor = 'Windsurf'; app = @('L:Programs\Windsurf\Windsurf.exe', 'P:Windsurf\Windsurf.exe'); ext = @('codeium.codeium', 'codeium.windsurf') }
    @{ name = 'Kiro'; kind = 'ide'; vendor = 'Amazon'; app = @('L:Programs\Kiro\Kiro.exe', 'P:Kiro\Kiro.exe') }
    @{ name = 'Trae'; kind = 'ide'; vendor = 'ByteDance'; app = @('L:Programs\Trae\Trae.exe') }
    # agent extensions for VS Code and its forks
    @{ name = 'GitHub Copilot'; kind = 'ext'; vendor = 'GitHub'; ext = @('github.copilot', 'github.copilot-chat') }
    @{ name = 'Roo Code'; kind = 'ext'; vendor = 'Roo Code'; ext = @('rooveterinaryinc.roo-cline') }
    @{ name = 'Kilo Code'; kind = 'ext'; vendor = 'Kilo Code'; ext = @('kilocode.kilo-code') }
    @{ name = 'Continue'; kind = 'ext'; vendor = 'Continue'; ext = @('continue.continue') }
    @{ name = 'Amazon Q'; kind = 'ext'; vendor = 'Amazon'; ext = @('amazonwebservices.amazon-q-vscode') }
    @{ name = 'Gemini Code Assist'; kind = 'ext'; vendor = 'Google'; ext = @('google.geminicodeassist') }
    @{ name = 'Tabnine'; kind = 'ext'; vendor = 'Tabnine'; ext = @('tabnine.tabnine-vscode') }
    # AI assistant apps
    @{ name = 'Claude desktop app'; kind = 'desktop'; vendor = 'Anthropic'; app = @('L:AnthropicClaude\claude.exe'); appx = @('*Claude*'); appxPublisher = '*Anthropic*' }
    @{ name = 'ChatGPT desktop app'; kind = 'desktop'; vendor = 'OpenAI'; appx = @('OpenAI.ChatGPT*') }
    @{ name = 'Microsoft Copilot'; kind = 'desktop'; vendor = 'Microsoft'; appx = @('Microsoft.Copilot') }
    @{ name = 'Perplexity'; kind = 'desktop'; vendor = 'Perplexity'; app = @('L:Programs\Perplexity\Perplexity.exe') }
    # local AI servers
    @{ name = 'Ollama'; kind = 'server'; vendor = 'Ollama'; app = @('L:Programs\Ollama\ollama.exe', 'P:Ollama\ollama.exe'); uninstall = '^Ollama'
       proc = @('ollama', 'ollama app'); appOsv = @('Go', 'github.com/ollama/ollama'); port = @(11434) }
    @{ name = 'LM Studio'; kind = 'server'; vendor = 'Element Labs'; uninstall = '^LM Studio'; proc = @('LM Studio', 'lms'); port = @(1234)
       app = @('L:Programs\LM Studio\LM Studio.exe', 'L:Programs\lm-studio\LM Studio.exe', 'P:LM Studio\LM Studio.exe', 'H:.lmstudio\bin\lms.exe') }
    @{ name = 'Jan'; kind = 'server'; vendor = 'Menlo Research'; app = @('L:Programs\jan\Jan.exe'); proc = @('Jan'); port = @(1337) }
    @{ name = 'GPT4All'; kind = 'server'; vendor = 'Nomic'; app = @('H:gpt4all\bin\chat.exe', 'P:gpt4all\bin\chat.exe'); uninstall = '^GPT4All'; port = @(4891) }
    @{ name = 'AnythingLLM'; kind = 'server'; vendor = 'Mintplex Labs'; proc = @('AnythingLLM'); port = @(3001)
       app = @('L:Programs\AnythingLLM\AnythingLLM.exe', 'L:Programs\anythingllm-desktop\AnythingLLM.exe') }
    @{ name = 'Msty'; kind = 'server'; vendor = 'CloudStack'; app = @('L:Programs\Msty\Msty.exe'); proc = @('Msty') }
    @{ name = 'llama.cpp server'; kind = 'server'; vendor = 'ggml'; proc = @('llama-server') }
    @{ name = 'KoboldCpp'; kind = 'server'; vendor = 'KoboldCpp'; proc = @('koboldcpp', 'koboldcpp_cu12', 'koboldcpp_nocuda'); port = @(5001) }
    @{ name = 'LocalAI'; kind = 'server'; vendor = 'LocalAI'; proc = @('local-ai') }
    @{ name = 'Open WebUI'; kind = 'server'; vendor = 'Open WebUI'; py = @('open-webui'); cmd = '(?i)open[-_]webui' }
    @{ name = 'vLLM'; kind = 'server'; vendor = 'vLLM'; py = @('vllm'); cmd = '(?i)\bvllm\b' }
    @{ name = 'LiteLLM'; kind = 'server'; vendor = 'BerriAI'; py = @('litellm'); cmd = '(?i)\blitellm\b'; port = @(4000) }
    @{ name = 'llama-cpp-python'; kind = 'server'; vendor = 'llama-cpp-python'; py = @('llama-cpp-python'); cmd = '(?i)llama_cpp\.server' }
    # agent frameworks (Python)
    @{ name = 'LangChain'; kind = 'framework'; vendor = 'LangChain'; py = @('langchain', 'langchain-core', 'langchain-community', 'langchain-experimental') }
    @{ name = 'LangGraph'; kind = 'framework'; vendor = 'LangChain'; py = @('langgraph') }
    @{ name = 'CrewAI'; kind = 'framework'; vendor = 'CrewAI'; py = @('crewai') }
    @{ name = 'AutoGen'; kind = 'framework'; vendor = 'Microsoft'; py = @('autogen-agentchat', 'pyautogen', 'ag2') }
    @{ name = 'LlamaIndex'; kind = 'framework'; vendor = 'LlamaIndex'; py = @('llama-index', 'llama-index-core') }
    @{ name = 'Semantic Kernel'; kind = 'framework'; vendor = 'Microsoft'; py = @('semantic-kernel') }
    @{ name = 'smolagents'; kind = 'framework'; vendor = 'Hugging Face'; py = @('smolagents') }
    @{ name = 'OpenAI Agents SDK'; kind = 'framework'; vendor = 'OpenAI'; py = @('openai-agents') }
    @{ name = 'Browser Use'; kind = 'framework'; vendor = 'Browser Use'; py = @('browser-use') }
    @{ name = 'Letta'; kind = 'framework'; vendor = 'Letta'; py = @('letta') }
)

# Editors that share the VS Code layout: extension folder (in the profile) and settings folder (in AppData\Roaming)
$Editors = @(
    @{ name = 'VS Code'; ext = '.vscode\extensions'; data = 'Code' }
    @{ name = 'VS Code Insiders'; ext = '.vscode-insiders\extensions'; data = 'Code - Insiders' }
    @{ name = 'VSCodium'; ext = '.vscode-oss\extensions'; data = 'VSCodium' }
    @{ name = 'Cursor'; ext = '.cursor\extensions'; data = 'Cursor' }
    @{ name = 'Windsurf'; ext = '.windsurf\extensions'; data = 'Windsurf' }
    @{ name = 'Kiro'; ext = '.kiro\extensions'; data = 'Kiro' }
    @{ name = 'Trae'; ext = '.trae\extensions'; data = 'Trae' }
)

# Global package folders, per user (and Python machine-wide)
$NpmDirs = @('R:npm\node_modules', 'L:pnpm\global\5\node_modules', 'H:.bun\install\global\node_modules')
$PythonDirs = @(
    'L:Programs\Python\Python*\Lib\site-packages', 'R:Python\Python*\site-packages',
    'H:pipx\venvs\*\Lib\site-packages', 'L:pipx\pipx\venvs\*\Lib\site-packages', 'R:uv\tools\*\Lib\site-packages',
    'H:anaconda3\Lib\site-packages', 'H:anaconda3\envs\*\Lib\site-packages',
    'H:miniconda3\Lib\site-packages', 'H:miniconda3\envs\*\Lib\site-packages',
    'P:Python*\Lib\site-packages', 'A:C:\Python*\Lib\site-packages',
    'M:anaconda3\Lib\site-packages', 'M:miniconda3\Lib\site-packages'
)

# Config files with MCP servers and keys. mcp: where the servers are (a property path,
# "projects.*.mcpServers" for each project); scope "all" checks the whole file for secrets,
# "mcp" only the MCP servers (for files with other content, such as chat history).
$AgentConfigs = @(
    @{ client = 'Claude Code'; file = 'H:.claude.json'; mcp = @('mcpServers', 'projects.*.mcpServers'); scope = 'mcp' }
    @{ client = 'Claude Code'; file = 'H:.claude\settings.json'; scope = 'all' }
    @{ client = 'Claude desktop app'; file = 'R:Claude\claude_desktop_config.json'; mcp = @('mcpServers'); scope = 'all' }
    @{ client = 'Cursor'; file = 'H:.cursor\mcp.json'; mcp = @('mcpServers'); scope = 'all' }
    @{ client = 'Windsurf'; file = 'H:.codeium\windsurf\mcp_config.json'; mcp = @('mcpServers'); scope = 'all' }
    @{ client = 'Gemini CLI'; file = 'H:.gemini\settings.json'; mcp = @('mcpServers'); scope = 'all' }
    @{ client = 'GitHub Copilot CLI'; file = 'H:.copilot\mcp-config.json'; mcp = @('mcpServers'); scope = 'all' }
    @{ client = 'OpenCode'; file = 'H:.config\opencode\opencode.json'; mcp = @('mcp'); scope = 'all' }
    @{ client = 'Continue'; file = 'H:.continue\config.json'; scope = 'all' }
    @{ client = 'Codex CLI'; file = 'H:.codex\config.toml'; format = 'toml'; scope = 'all' }
    @{ client = 'Continue'; file = 'H:.continue\config.yaml'; format = 'text'; scope = 'all' }
    @{ client = 'Aider'; file = 'H:.aider.conf.yml'; format = 'text'; scope = 'all' }
)
foreach ($e in $Editors) {
    $AgentConfigs += @{ client = $e.name; file = "R:$($e.data)\User\mcp.json"; mcp = @('servers'); scope = 'all' }
    $AgentConfigs += @{ client = $e.name; file = "R:$($e.data)\User\settings.json"; mcp = @('mcp.servers'); scope = 'mcp'; jsonc = $true }
    foreach ($x in @(@('Cline', 'saoudrizwan.claude-dev\settings\cline_mcp_settings.json'), @('Roo Code', 'rooveterinaryinc.roo-cline\settings\mcp_settings.json'),
                     @('Kilo Code', 'kilocode.kilo-code\settings\mcp_settings.json'))) {
        $AgentConfigs += @{ client = "$($x[0]) in $($e.name)"; file = "R:$($e.data)\User\globalStorage\$($x[1])"; mcp = @('mcpServers'); scope = 'all' }
    }
}

# Secrets in plain text: known token formats (High) and values of keys named like a secret (Medium)
$SecretPatterns = @(
    @{ kind = 'Anthropic API key'; re = '(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}' }
    @{ kind = 'OpenAI API key'; re = '(?<![A-Za-z0-9])sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}' }
    @{ kind = 'GitHub token'; re = '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}' }
    @{ kind = 'GitLab token'; re = 'glpat-[A-Za-z0-9_-]{20,}' }
    @{ kind = 'Slack token'; re = 'xox[abposr]-[A-Za-z0-9-]{10,}' }
    @{ kind = 'AWS access key'; re = '\b(AKIA|ASIA)[0-9A-Z]{16}\b' }
    @{ kind = 'Google API key'; re = 'AIza[0-9A-Za-z_-]{35}' }
    @{ kind = 'Hugging Face token'; re = '\bhf_[A-Za-z0-9]{30,}' }
    @{ kind = 'Stripe key'; re = '\b(sk|rk)_live_[A-Za-z0-9]{20,}' }
    @{ kind = 'Bearer token'; re = '(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}' }
    @{ kind = 'Private key'; re = '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
)
$SecretKeyRe = '(?i)(api[_-]?key|apikey|token|secret|passw(or)?d|pwd|credential|^auth(orization)?$|access[_-]?key|private[_-]?key|connection[_-]?string)'
$NotSecretKeyRe = '(?i)(path|file|dir|url|uri|env|var|name|type|mode|count|limit|max|min|budget|header|prefix|helper|command|endpoint|expires?)$|^max_?tokens$'

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $Message
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 2MB) {
            Move-Item $LogFile "$LogFile.1" -Force
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Write-TextFile([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

function Write-JsonFile([string]$Path, $Object) {
    Write-TextFile $Path (ConvertTo-Json -InputObject $Object -Depth 8)
}

function Get-Clip([string]$Text, [int]$Max) {
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max - 3) + '...'
}

# -1, 0 or 1. Compares the numbers in two version strings ("8u401" < "8u511b33").
function Compare-Version([string]$A, [string]$B) {
    $x = @([regex]::Matches($A, '\d+') | ForEach-Object { [long]$_.Value })
    $y = @([regex]::Matches($B, '\d+') | ForEach-Object { [long]$_.Value })
    $n = [Math]::Max($x.Count, $y.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $p = if ($i -lt $x.Count) { $x[$i] } else { 0 }
        $q = if ($i -lt $y.Count) { $y[$i] } else { 0 }
        if ($p -ne $q) { return [Math]::Sign($p - $q) }
    }
    0
}

function Initialize-DataDir {
    if (-not (Test-Path $DataDir)) {
        # same access as install-local.ps1 sets: SYSTEM and Administrators only
        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
        & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'reports\history') | Out-Null
}

function Read-Config([string]$Path) {
    $cfg = [ordered]@{}
    foreach ($k in $DefaultConfig.Keys) { $cfg[$k] = $DefaultConfig[$k] }
    if (Test-Path $Path) {
        $j = Get-Content -Path $Path -Raw | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) {
            if (-not $p.Name.StartsWith('_')) { $cfg[$p.Name] = $p.Value }
        }
    }
    $cfg
}

function Read-TextFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $f = Get-Item -LiteralPath $Path -Force
    if ($f.Length -gt 50MB) { throw "$Path is larger than 50 MB" }
    [IO.File]::ReadAllText($f.FullName)
}

# VS Code style JSON: comments and trailing commas are allowed
function ConvertFrom-Jsonc([string]$Text) {
    $sb = New-Object Text.StringBuilder
    $inStr = $false; $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inStr) {
            [void]$sb.Append($c)
            if ($c -eq '\' -and $i + 1 -lt $n) { [void]$sb.Append($Text[$i + 1]); $i += 2; continue }
            if ($c -eq '"') { $inStr = $false }
            $i++; continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$sb.Append($c); $i++; continue }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/') { while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }; continue }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '*') {
            $j = $Text.IndexOf('*/', $i + 2); $i = if ($j -lt 0) { $n } else { $j + 2 }; continue
        }
        if ($c -eq ',') {
            $j = $i + 1
            while ($j -lt $n -and [char]::IsWhiteSpace($Text[$j])) { $j++ }
            if ($j -lt $n -and ($Text[$j] -eq '}' -or $Text[$j] -eq ']')) { $i++; continue }
        }
        [void]$sb.Append($c); $i++
    }
    $sb.ToString() | ConvertFrom-Json
}

function Read-JsonFile([string]$Path, [bool]$Jsonc) {
    $t = Read-TextFile $Path
    if ($null -eq $t -or -not $t.Trim()) { return $null }
    if (-not $Jsonc) { try { return ($t | ConvertFrom-Json) } catch { } }
    try { return (ConvertFrom-Jsonc $t) } catch { throw "cannot read ${Path}: $($_.Exception.Message)" }
}

# a property of a JSON object; names may contain dots ("chat.tools.autoApprove")
function Get-JsonValue($Object, [string[]]$Names) {
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o -or -not ($o -is [psobject])) { return $null }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function Get-JsonProperties($Object) {
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [ValueType] -or $Object -is [array]) { return @() }
    @($Object.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })
}

function Test-NameMatch([string]$Name, $Patterns) {
    foreach ($p in @($Patterns)) { if ($p -and $Name -like "$p") { return $true } }
    $false
}

function Get-Masked([string]$Value) {
    $v = $Value.Trim()
    $keep = if ($v.Length -ge 16) { 6 } elseif ($v.Length -ge 10) { 3 } else { 1 }
    '{0}... ({1} characters)' -f $v.Substring(0, $keep), $v.Length
}

# --------------------------------------------------------------------------
# machine and user profiles
# --------------------------------------------------------------------------

function Get-HostInfo {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $name = if ($cs.DNSHostName) { $cs.DNSHostName } else { $env:COMPUTERNAME }
    $fqdn = if ($cs.PartOfDomain) { '{0}.{1}' -f $name, $cs.Domain } else { $name }
    $release = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
    [pscustomobject]@{
        host      = $fqdn.ToLower()
        short     = $name.ToLower()
        os        = "$($os.Caption)".Trim()
        version   = "$($os.Version)"
        ubr       = "$($cv.UBR)"
        release   = "$release"
        edition   = "$($cv.EditionID)"
        server    = ($os.ProductType -ne 1)
        last_boot = $os.LastBootUpTime.ToString('s')
    }
}

function Get-UserProfiles {
    $list = @()
    try {
        foreach ($p in @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath })) {
            $name = Split-Path $p.LocalPath -Leaf
            try { $name = (New-Object Security.Principal.SecurityIdentifier($p.SID)).Translate([Security.Principal.NTAccount]).Value } catch { }
            $list += [pscustomobject]@{ user = $name; sid = "$($p.SID)"; home = "$($p.LocalPath)" }
        }
    } catch { }
    if (-not $list) {
        $skip = @('Public', 'Default', 'Default User', 'All Users')
        foreach ($d in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name })) {
            $list += [pscustomobject]@{ user = $d.Name; sid = ''; home = $d.FullName }
        }
    }
    @($list | Where-Object { Test-Path -LiteralPath $_.home })
}

# a catalog path ("L:Programs\Ollama\ollama.exe") in one user's profile, or machine-wide without a profile
function Resolve-AiPath([string]$Spec, $Profile) {
    $k = $Spec.Substring(0, 1); $rel = $Spec.Substring(2)
    switch ($k) {
        'H' { if ($Profile) { return @(Join-Path $Profile.home $rel) } }
        'L' { if ($Profile) { return @(Join-Path (Join-Path $Profile.home 'AppData\Local') $rel) } }
        'R' { if ($Profile) { return @(Join-Path (Join-Path $Profile.home 'AppData\Roaming') $rel) } }
        'P' { if (-not $Profile) { return @(@($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { Join-Path $_ $rel }) } }
        'M' { if (-not $Profile) { return @(Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $rel) } }
        'A' { if (-not $Profile) { return @($rel) } }
    }
    @()
}

function Get-FileVersion([string]$Path) {
    $v = ''
    try { $v = "$((Get-Item -LiteralPath $Path -Force).VersionInfo.ProductVersion)".Trim() } catch { }
    if ($v -match '\d+(\.\d+)+') { return $Matches[0] }
    ''
}

function Get-UninstallEntries {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    # per-user programs: only the users whose registry is loaded (logged on) can be read
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    foreach ($k in $keys) {
        $sid = if ($k -match 'HKEY_USERS\\([^\\]+)\\') { $Matches[1] } else { '' }
        foreach ($e in @(Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)) {
            if (-not $e.DisplayName) { continue }
            [pscustomobject]@{ name = "$($e.DisplayName)".Trim(); version = "$($e.DisplayVersion)".Trim()
                               location = "$($e.InstallLocation)".Trim(); sid = $sid }
        }
    }
}

function Get-AiAppxPackages {
    @(Get-AppxPackage -AllUsers -ErrorAction Stop | ForEach-Object {
        $users = @($_.PackageUserInformation | Where-Object { "$($_.InstallState)" -eq 'Installed' } | ForEach-Object { "$($_.UserSecurityId.Username)" })
        [pscustomobject]@{ name = "$($_.Name)"; publisher = "$($_.Publisher)"; version = "$($_.Version)"; path = "$($_.InstallLocation)"; users = $users }
    })
}

function Get-AiProcesses {
    @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ pid = [int]$_.ProcessId; name = "$($_.Name)"; path = "$($_.ExecutablePath)"; cmd = "$($_.CommandLine)" }
    })
}

function Get-Listeners {
    try {
        return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ address = "$($_.LocalAddress)"; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess }
        })
    } catch { }
    # older systems: netstat (the state column is translated, so match the empty remote address)
    @(& netstat.exe -ano | ForEach-Object {
        if ($_ -match '^\s*TCP\s+(\S+):(\d+)\s+(0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)\s*$') {
            [pscustomobject]@{ address = $Matches[1].Trim('[', ']'); port = [int]$Matches[2]; pid = [int]$Matches[4] }
        }
    })
}

function Get-AiServices {
    @(Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
        $p = "$($_.PathName)"
        if ($p -match '(?i)\bnssm(\.exe)?\b') {
            # services wrapped by NSSM: the real program is in the service's Parameters
            $app = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\Parameters" -ErrorAction SilentlyContinue).Application
            if ($app) { $p = "$app $p" }
        }
        [pscustomobject]@{ name = "$($_.Name)"; display = "$($_.DisplayName)"; path = $p; account = "$($_.StartName)"; state = "$($_.State)" }
    })
}

# an environment variable, machine-wide and for each logged-on user
function Get-EnvValues([string]$Name, $Profiles) {
    $out = @()
    $m = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue).$Name
    if ($m) { $out += [pscustomobject]@{ scope = 'machine'; user = ''; value = "$m" } }
    foreach ($p in $Profiles) {
        if (-not $p.sid) { continue }
        $v = (Get-ItemProperty "Registry::HKEY_USERS\$($p.sid)\Environment" -ErrorAction SilentlyContinue).$Name
        if ($v) { $out += [pscustomobject]@{ scope = 'user'; user = $p.user; value = "$v" } }
    }
    $out
}

# --------------------------------------------------------------------------
# AI agents
# --------------------------------------------------------------------------

function New-AiInstall($Entry, [string]$Version, [string]$User, [string]$Path, [string]$Source, [string]$Detail, $Osv) {
    [pscustomobject]@{
        name = $Entry.name; kind = $Entry.kind; kind_label = $AiKinds[$Entry.kind]; vendor = "$($Entry.vendor)"
        version = $Version; user = $User; path = $Path; source = $Source; detail = $Detail
        osv_ecosystem = $(if ($Osv) { $Osv[0] } else { '' }); osv_package = $(if ($Osv) { $Osv[1] } else { '' })
        running = $false; pids = @()
    }
}

function Find-AiInstalls($Profiles) {
    $found = New-Object Collections.Generic.List[object]
    $targets = @($Profiles) + @($null)
    foreach ($p in $targets) {
        $user = if ($p) { $p.user } else { '(all users)' }
        foreach ($e in $AiCatalog) {
            # programs: the first file found counts (LM Studio.exe, not also its lms.exe)
            $seen = $false
            foreach ($spec in @($e.app)) {
                if (-not $spec -or $seen) { continue }
                foreach ($path in @(Resolve-AiPath $spec $p)) {
                    if ($seen -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                    $seen = $true
                    $ver = ''
                    if ($e.versions -and $p) {
                        $vd = @(Resolve-AiPath $e.versions $p)[0]
                        $vs = @(Get-ChildItem -LiteralPath $vd -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } | ForEach-Object { $_.Name })
                        foreach ($x in $vs) { if (-not $ver -or (Compare-Version $x $ver) -gt 0) { $ver = $x } }
                    }
                    if (-not $ver) { $ver = Get-FileVersion $path }
                    $found.Add((New-AiInstall $e $ver $user $path 'program' '' $e.appOsv))
                }
            }
            if (-not $p) { continue }
            # global npm packages
            foreach ($pkg in @($e.npm)) {
                if (-not $pkg) { continue }
                foreach ($spec in $NpmDirs) {
                    $dir = Join-Path @(Resolve-AiPath $spec $p)[0] $pkg
                    $pj = Join-Path $dir 'package.json'
                    if (-not (Test-Path -LiteralPath $pj -PathType Leaf)) { continue }
                    $ver = $(try { "$((Read-JsonFile $pj $false).version)" } catch { '' })
                    $found.Add((New-AiInstall $e $ver $user $dir 'npm' "npm package $pkg" @('npm', $pkg)))
                }
            }
        }
        if (-not $p) { continue }
        # editor extensions: the newest version of each extension in each editor
        foreach ($ed in $Editors) {
            $dir = Join-Path $p.home $ed.ext
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            $best = @{}
            foreach ($d in @(Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)) {
                if ($d.Name -notmatch '^(?<id>.+?)-(?<v>\d+\.\d+\.\d+)') { continue }
                $id = $Matches['id'].ToLower(); $v = $Matches['v']
                if (-not $best.ContainsKey($id) -or (Compare-Version $v $best[$id].v) -gt 0) { $best[$id] = @{ v = $v; path = $d.FullName } }
            }
            foreach ($e in $AiCatalog) {
                foreach ($id in @($e.ext)) {
                    if ($id -and $best.ContainsKey($id)) {
                        $found.Add((New-AiInstall $e $best[$id].v $user $best[$id].path 'extension' "$($ed.name) extension $id" $null))
                    }
                }
            }
        }
    }
    # Python packages, per user and machine-wide
    $pyNames = @{}
    foreach ($e in $AiCatalog) { foreach ($n in @($e.py)) { if ($n) { $pyNames[$n] = $e } } }
    foreach ($p in $targets) {
        $user = if ($p) { $p.user } else { '(all users)' }
        foreach ($spec in $PythonDirs) {
            foreach ($base in @(Resolve-AiPath $spec $p)) {
                $dirs = @()
                try { $dirs = @(Get-ChildItem -Path (Join-Path $base '*.dist-info') -Directory -ErrorAction SilentlyContinue) } catch { }   # a drive that doesn't exist
                foreach ($d in $dirs) {
                    if ($d.Name -notmatch '^(?<n>[^-]+)-(?<v>[^-]+)\.dist-info$') { continue }
                    $n = ($Matches['n'] -replace '[-_.]+', '-').ToLower(); $v = $Matches['v']
                    if (-not $pyNames.ContainsKey($n)) { continue }
                    $e = $pyNames[$n]
                    $found.Add((New-AiInstall $e $v $user $d.Parent.FullName 'python' "Python package $n" @('PyPI', $n)))
                }
            }
        }
    }
    $found.ToArray()
}

# programs found in the Uninstall list or as Store apps, where the paths above found nothing
function Find-AiRegistered($Installs, $Profiles) {
    $out = @()
    $bySid = @{}
    foreach ($p in $Profiles) { if ($p.sid) { $bySid[$p.sid] = $p.user } }
    $have = @{}
    foreach ($i in $Installs) { $have["$($i.name)|$($i.user)"] = $true }
    foreach ($u in @(Get-UninstallEntries)) {
        foreach ($e in $AiCatalog) {
            if (-not $e.uninstall -or $u.name -notmatch $e.uninstall) { continue }
            $user = if ($u.sid) { if ($bySid.ContainsKey($u.sid)) { $bySid[$u.sid] } else { $u.sid } } else { '(all users)' }
            if ($have.ContainsKey("$($e.name)|$user") -or $have.ContainsKey("$($e.name)|(all users)")) { continue }
            $have["$($e.name)|$user"] = $true
            $out += New-AiInstall $e $u.version $user $(if ($u.location) { $u.location } else { $u.name }) 'program' 'from the list of installed programs' $e.appOsv
        }
    }
    $appx = @()
    try { $appx = @(Get-AiAppxPackages) } catch { }   # not on Server Core
    foreach ($a in $appx) {
        foreach ($e in $AiCatalog) {
            if (-not $e.appx -or -not (Test-NameMatch $a.name $e.appx)) { continue }
            if ($e.appxPublisher -and $a.publisher -notlike $e.appxPublisher) { continue }
            $users = if (@($a.users).Count) { @($a.users) -join ', ' } else { '(all users)' }
            if ($have.ContainsKey("$($e.name)|$users")) { continue }
            $have["$($e.name)|$users"] = $true
            $out += New-AiInstall $e $a.version $users $a.path 'store app' "Store app $($a.name)" $null
        }
    }
    $out
}

function Test-AiCommand($Entry, [string]$Name, [string]$Command) {
    $base = [IO.Path]::GetFileNameWithoutExtension($Name)
    foreach ($p in @($Entry.proc)) { if ($p -and $base -eq $p) { return $true } }
    if ($Entry.cmd -and $Command -match $Entry.cmd) { return $true }
    $false
}

# which AI tools run now, which ports the local AI servers listen on, and AI servers installed as services
function Get-AiRuntime($Installs) {
    $procs = @(Get-AiProcesses)
    $byPid = @{}
    $extra = @()
    foreach ($pr in $procs) {
        $hit = $null
        foreach ($i in $Installs) {
            if ($i.source -eq 'store app' -or -not $i.path) { continue }
            $dir = if ($i.source -eq 'program') { Split-Path $i.path -Parent } else { $i.path }
            if (-not $dir) { continue }
            # programs in a shared folder such as .local\bin: only the program itself
            $same = $pr.path -and $(if ($i.source -eq 'program' -and (Split-Path $dir -Leaf) -eq 'bin') { $pr.path -eq $i.path } else { $pr.path.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) })
            if ($same -or
                ($i.source -eq 'npm' -and $pr.cmd -and $pr.cmd.IndexOf($dir, [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
                $i.running = $true; $i.pids += $pr.pid
                if (-not $hit) { $hit = $i.name }
            }
        }
        if (-not $hit) {
            foreach ($e in $AiCatalog) {
                if ($e.kind -ne 'server' -or -not (Test-AiCommand $e $pr.name $pr.cmd)) { continue }
                $hit = $e.name
                # a server found only by its process (llama.cpp, KoboldCpp, ...): add it to the list
                $known = @($Installs + $extra | Where-Object { $_.name -eq $e.name })
                if (-not $known) {
                    $x = New-AiInstall $e $(if ($pr.path) { Get-FileVersion $pr.path } else { '' }) '' $(if ($pr.path) { $pr.path } else { $pr.name }) 'process' 'running process' $null
                    $x.running = $true; $x.pids = @($pr.pid)
                    $extra += $x
                } else {
                    foreach ($k in $known) { $k.running = $true; if ($k.pids -notcontains $pr.pid) { $k.pids += $pr.pid } }
                }
                break
            }
        }
        if ($hit) { $byPid[$pr.pid] = @{ name = $hit; process = $pr.name; path = $pr.path } }
    }
    $listen = @()
    $ports = @{}
    foreach ($e in $AiCatalog) { foreach ($n in @($e.port)) { if ($n) { $ports[[int]$n] = $e.name } } }
    foreach ($l in @(Get-Listeners)) {
        $who = $byPid[$l.pid]
        $name = $null; $note = ''
        if ($who) { $name = $who.name }
        elseif ($l.port -eq 11434) {
            # Ollama's port, opened by another program (Docker, WSL or a proxy forwarding it)
            $pn = @($procs | Where-Object { $_.pid -eq $l.pid } | ForEach-Object { $_.name })[0]
            $name = 'Ollama'; $note = "port $($l.port) is Ollama's; it is opened by $(if ($pn) { $pn } else { "process $($l.pid)" }), probably forwarding to Ollama in a container or WSL"
            $who = @{ process = $pn; path = '' }
        }
        if (-not $name) { continue }
        $a = $l.address.Trim('[', ']')
        $listen += [pscustomobject]@{
            name = $name; address = $a; port = $l.port; pid = $l.pid; process = "$($who.process)"; path = "$($who.path)"
            exposed = -not (Test-LoopbackHost $a); note = $note
        }
    }
    # one entry per server, address and port (IPv4 and IPv6 sockets of the same server are kept apart)
    $listen = @($listen | Sort-Object name, port, address -Unique)
    $services = @()
    foreach ($s in @(Get-AiServices)) {
        foreach ($e in $AiCatalog) {
            if ($e.kind -ne 'server') { continue }
            $match = $false
            foreach ($p in @($e.proc)) { if ($p -and $s.path -match ('(?i)(^|[\\/"\s])' + [regex]::Escape($p) + '(\.exe)?("|\s|$)')) { $match = $true } }
            if ($e.cmd -and $s.path -match $e.cmd) { $match = $true }
            if (-not $match) { continue }
            $services += [pscustomobject]@{ name = $e.name; service = $s.name; display = $s.display; path = $s.path; account = $s.account; state = $s.state
                                            system = ($s.account -eq '' -or $s.account -match '(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM|\.\\LocalSystem)$') }
            break
        }
    }
    [pscustomobject]@{ extra = $extra; listeners = $listen; services = $services }
}

function Test-LoopbackHost([string]$HostName) {
    $h = $HostName.Trim().Trim('[', ']').ToLower()
    $h -eq 'localhost' -or $h -eq '::1' -or $h -eq '0:0:0:0:0:0:0:1' -or $h -match '^127\.' -or $h -match '^::ffff:127\.'
}

# "0.0.0.0", "0.0.0.0:11434", "http://[::]:11434", ":11434" -> the host part
function Get-BindHost([string]$Value) {
    $v = ("$Value".Trim() -replace '^[a-zA-Z]+://', '').Split('/')[0]
    if ($v -match '^\[(.*)\](:\d+)?$') { return $Matches[1] }
    if ($v.Split(':').Count -gt 2) { return $v }
    $v.Split(':')[0]
}

# --------------------------------------------------------------------------
# agent settings
# --------------------------------------------------------------------------

function New-SettingIssue([string]$Agent, [string]$User, [string]$File, [string]$Setting, [string]$Severity, [string]$Text, [string]$Fix) {
    [pscustomobject]@{ agent = $Agent; user = $User; file = $File; setting = $Setting; severity = $Severity; text = $Text; fix = $Fix }
}

function Get-AgentSettingIssues($Profiles) {
    $out = @()
    # Claude Code: the organization's managed settings can block bypass mode for everyone
    $managedFile = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json'
    $managed = $null
    try { $managed = Read-JsonFile $managedFile $false } catch { }
    $bypassBlocked = "$(Get-JsonValue $managed @('permissions', 'disableBypassPermissionsMode'))" -eq 'disable'
    if ("$(Get-JsonValue $managed @('permissions', 'defaultMode'))" -eq 'bypassPermissions' -and -not $bypassBlocked) {
        $out += New-SettingIssue 'Claude Code' '(all users)' $managedFile 'permissions.defaultMode = "bypassPermissions"' 'High' `
            'The managed settings start every Claude Code session without permission prompts: it edits files and runs commands without asking.' `
            'Remove defaultMode "bypassPermissions" from the managed settings, and set permissions.disableBypassPermissionsMode to "disable".'
    }
    foreach ($p in $Profiles) {
        $f = Join-Path $p.home '.claude\settings.json'
        $j = $null; try { $j = Read-JsonFile $f $false } catch { }
        if ($j -and -not $bypassBlocked) {
            if ("$(Get-JsonValue $j @('permissions', 'defaultMode'))" -eq 'bypassPermissions') {
                $out += New-SettingIssue 'Claude Code' $p.user $f 'permissions.defaultMode = "bypassPermissions"' 'Medium' `
                    'Claude Code starts without permission prompts: it edits files and runs commands without asking, so a prompt injection in a file or web page can run commands as this user.' `
                    'Remove "defaultMode": "bypassPermissions" from the file. To block it for everyone, set permissions.disableBypassPermissionsMode to "disable" in C:\Program Files\ClaudeCode\managed-settings.json.'
            } elseif ((Get-JsonValue $j @('skipDangerousModePermissionPrompt')) -eq $true) {
                $out += New-SettingIssue 'Claude Code' $p.user $f 'skipDangerousModePermissionPrompt = true' 'Low' `
                    'The user has turned off the warning before bypass permissions mode, so sessions can start without permission prompts.' `
                    'Remove the setting, or block bypass mode with permissions.disableBypassPermissionsMode = "disable" in the managed settings.'
            }
        }
        # Codex CLI
        $f = Join-Path $p.home '.codex\config.toml'
        $t = $null; try { $t = Read-TextFile $f } catch { }
        if ($t) {
            $never = $t -match '(?m)^\s*approval_policy\s*=\s*"never"'
            $full = $t -match '(?m)^\s*sandbox_mode\s*=\s*"danger-full-access"'
            if ($never -and $full) {
                $out += New-SettingIssue 'Codex CLI' $p.user $f 'approval_policy = "never", sandbox_mode = "danger-full-access"' 'High' `
                    'Codex runs every command without asking and without its sandbox: full access to the files and network of this user.' `
                    'Remove both lines (the defaults ask before risky commands and use the sandbox), or set approval_policy = "on-request".'
            } elseif ($never) {
                $out += New-SettingIssue 'Codex CLI' $p.user $f 'approval_policy = "never"' 'Medium' `
                    'Codex never asks before running a command; only its sandbox limits what the commands can do.' 'Set approval_policy = "on-request", or remove the line.'
            } elseif ($full) {
                $out += New-SettingIssue 'Codex CLI' $p.user $f 'sandbox_mode = "danger-full-access"' 'Medium' `
                    'Codex runs commands outside its sandbox, with full access to the files and network of this user.' 'Use sandbox_mode = "workspace-write", or remove the line.'
            }
        }
        # Gemini CLI
        $f = Join-Path $p.home '.gemini\settings.json'
        $j = $null; try { $j = Read-JsonFile $f $false } catch { }
        if ("$(Get-JsonValue $j @('general', 'defaultApprovalMode'))" -eq 'yolo') {
            $out += New-SettingIssue 'Gemini CLI' $p.user $f 'general.defaultApprovalMode = "yolo"' 'Medium' `
                'Gemini CLI approves every tool call, including shell commands, without asking.' 'Set general.defaultApprovalMode to "default", or remove it.'
        }
        # VS Code and its forks: agent mode tools approved without asking
        foreach ($ed in $Editors) {
            $f = Join-Path $p.home "AppData\Roaming\$($ed.data)\User\settings.json"
            $j = $null; try { $j = Read-JsonFile $f $true } catch { }
            if (-not $j) { continue }
            foreach ($k in 'chat.tools.global.autoApprove', 'chat.tools.autoApprove') {
                if ((Get-JsonValue $j @($k)) -eq $true) {
                    $out += New-SettingIssue "$($ed.name) agent mode" $p.user $f "$k = true" 'Medium' `
                        'Agent mode runs every tool, including terminal commands, without asking for approval.' "Remove `"$k`" from the user settings, or set it to false."
                    break
                }
            }
        }
        # Aider
        $f = Join-Path $p.home '.aider.conf.yml'
        $t = $null; try { $t = Read-TextFile $f } catch { }
        if ($t -and $t -match '(?m)^\s*yes-always\s*:\s*true') {
            $out += New-SettingIssue 'Aider' $p.user $f 'yes-always: true' 'Medium' `
                'Aider answers yes to every question, including running shell commands.' 'Remove yes-always from the file.'
        }
    }
    $out
}

# --------------------------------------------------------------------------
# MCP servers and secrets in agent configs
# --------------------------------------------------------------------------

function Test-Placeholder([string]$Value) {
    $v = $Value.Trim()
    $v.Length -lt 8 -or $v -match '^\$\{.*\}$' -or $v -match '^\$env:' -or $v -match '^%[^%]+%$' -or $v -match '\{\{.*\}\}' -or
        $v -match '^<.*>$' -or $v -match '(?i)your[-_ ]|placeholder|example|changeme|xxxx|\*\*\*\*' -or $v -match '^[A-Z][A-Z0-9_]+$' -or
        $v -match '^(true|false|null|\d+)$' -or $v -match '^[A-Za-z]:\\' -or $v -match '^[~.]?/' -or $v -match '\s'
}

# secrets in one value: a known token format anywhere, or the value of a key named like a secret
function Find-SecretsInValue([string]$Key, [string]$Value) {
    $out = @()
    foreach ($s in $SecretPatterns) {
        $m = [regex]::Match($Value, $s.re)
        if ($m.Success) { $out += [pscustomobject]@{ kind = $s.kind; strong = $true; masked = (Get-Masked $m.Value) }; return $out }
    }
    $parts = @($Key -split '[.\[\]]' | Where-Object { $_ })
    $last = if ($parts.Count) { $parts[-1] } else { '' }
    if ($last -and $last -match $SecretKeyRe -and $last -notmatch $NotSecretKeyRe -and -not (Test-Placeholder $Value)) {
        $out += [pscustomobject]@{ kind = 'value of ' + $last; strong = $false; masked = (Get-Masked $Value) }
    }
    $out
}

function Find-SecretsInJson($Node, [string]$Path) {
    $out = @()
    if ($null -eq $Node) { return $out }
    if ($Node -is [string]) {
        foreach ($s in @(Find-SecretsInValue $Path $Node)) { $s | Add-Member -NotePropertyName key -NotePropertyValue $Path; $out += $s }
        return $out
    }
    if ($Node -is [array]) {
        for ($i = 0; $i -lt $Node.Count; $i++) { $out += @(Find-SecretsInJson $Node[$i] "$Path[$i]") }
        return $out
    }
    foreach ($p in @(Get-JsonProperties $Node)) {
        $out += @(Find-SecretsInJson $p.Value $(if ($Path) { "$Path.$($p.Name)" } else { $p.Name }))
    }
    $out
}

function Find-SecretsInText([string]$Text) {
    $out = @()
    $n = 0
    foreach ($line in ($Text -split "`n")) {
        $n++
        if ($line -match '^\s*#') { continue }
        $hits = @()
        foreach ($m in [regex]::Matches($line, '(?<k>[A-Za-z0-9_.-]+)["'']?\s*[:=]\s*["'']?(?<v>[^"''\s,}#]+)')) {
            $hits += @(Find-SecretsInValue $m.Groups['k'].Value $m.Groups['v'].Value | ForEach-Object { $_ | Add-Member -NotePropertyName key -NotePropertyValue "$($m.Groups['k'].Value) (line $n)" -PassThru })
        }
        if (-not $hits) {
            $hits = @(Find-SecretsInValue '' $line | ForEach-Object { $_ | Add-Member -NotePropertyName key -NotePropertyValue "line $n" -PassThru })
        }
        $out += $hits
    }
    $out
}

# package an MCP server starts with npx, uvx, ...; pinned when it names a version
function Get-McpPackage([string]$Command, $McpArgs) {
    $exe = [IO.Path]::GetFileNameWithoutExtension(("$Command" -split '[\\/]')[-1]).ToLower()
    $a = @($McpArgs | ForEach-Object { "$_" })
    if ($exe -eq 'cmd' -and $a.Count -ge 2 -and $a[0] -match '^/[cCkK]$') {
        # "cmd /c npx -y package": the usual way to start npx on Windows
        $exe = [IO.Path]::GetFileNameWithoutExtension(($a[1] -split '[\\/]')[-1]).ToLower()
        $a = @($a | Select-Object -Skip 2)
    }
    $rest = @()
    switch ($exe) {
        { $_ -in 'npx', 'bunx', 'uvx' } { $rest = $a }
        'pnpm' { if ($a.Count -and $a[0] -eq 'dlx') { $rest = @($a | Select-Object -Skip 1) } }
        'pipx' { if ($a.Count -and $a[0] -eq 'run') { $rest = @($a | Select-Object -Skip 1) } }
        default { return $null }
    }
    $pkg = $null
    for ($i = 0; $i -lt $rest.Count; $i++) {
        $x = $rest[$i]
        if ($x -in '--from', '--package', '-p') { if ($i + 1 -lt $rest.Count) { $pkg = $rest[$i + 1] }; break }
        if ($x.StartsWith('-')) { continue }
        $pkg = $x; break
    }
    if (-not $pkg) { return $null }
    $pinned = if ($exe -in 'npx', 'bunx', 'pnpm') { $pkg -match '^(@[^/]+/)?[^@]+@\d' } else { $pkg -match '(==|@)\d' }
    [pscustomobject]@{ runner = $exe; package = $pkg; pinned = [bool]$pinned }
}

function New-McpServer([string]$Client, [string]$User, [string]$File, [string]$Name, [string]$Command, $McpArgs, [string]$McpUrl, [string]$Type) {
    $pkg = if ($Command) { Get-McpPackage $Command $McpArgs } else { $null }
    $transport = if ($McpUrl) { if ($Type -match '(?i)sse') { 'sse' } else { 'http' } } else { 'stdio' }
    $local = $false
    if ($McpUrl -match '^[a-zA-Z]+://([^/]+)') { $local = Test-LoopbackHost (Get-BindHost $Matches[1]) }
    [pscustomobject]@{
        client = $Client; user = $User; file = $File; name = $Name; transport = $transport
        command = $(if ($Command) { (@($Command) + @($McpArgs | ForEach-Object { "$_" })) -join ' ' } else { '' })
        url = $McpUrl; package = $(if ($pkg) { $pkg.package } else { '' }); pinned = $(if ($pkg) { $pkg.pinned } else { $null })
        plain_http = ($McpUrl -match '^http://' -and -not $local); secrets = 0
    }
}

function Get-McpFromJson($Json, [string[]]$Where, [string]$Client, [string]$User, [string]$File) {
    $out = @()
    foreach ($w in $Where) {
        $blocks = @()
        if ($w -like 'projects.*.*') {
            $rest = $w.Substring('projects.*.'.Length)
            foreach ($pp in @(Get-JsonProperties (Get-JsonValue $Json @('projects')))) {
                $b = Get-JsonValue $pp.Value @($rest)
                if ($b) { $blocks += @{ prefix = "projects.$($pp.Name).$rest"; node = $b; project = $pp.Name } }
            }
        } else {
            $b = Get-JsonValue $Json @($w -split '\.')
            if ($null -eq $b) { $b = Get-JsonValue $Json @($w) }
            if ($b) { $blocks += @{ prefix = $w; node = $b; project = '' } }
        }
        foreach ($blk in $blocks) {
            foreach ($s in @(Get-JsonProperties $blk.node)) {
                $d = $s.Value
                $cmd = Get-JsonValue $d @('command'); $args2 = @(Get-JsonValue $d @('args'))
                if ($cmd -is [array]) { $args2 = @($cmd | Select-Object -Skip 1) + $args2; $cmd = @($cmd)[0] }
                $url = "$(Get-JsonValue $d @('url'))"
                foreach ($k in 'httpUrl', 'serverUrl') { if (-not $url) { $url = "$(Get-JsonValue $d @($k))" } }
                $name = if ($blk.project) { "$($s.Name) (project $($blk.project))" } else { $s.Name }
                $m = New-McpServer $Client $User $File $name "$cmd" @($args2 | Where-Object { $null -ne $_ }) $url "$(Get-JsonValue $d @('type'))"
                $m | Add-Member -NotePropertyName json_path -NotePropertyValue "$($blk.prefix).$($s.Name)"
                $m | Add-Member -NotePropertyName json_node -NotePropertyValue $d
                $out += $m
            }
        }
    }
    $out
}

# Codex keeps its MCP servers in TOML: [mcp_servers.<name>] with command, args, url and env
function Get-McpFromToml([string]$Text, [string]$Client, [string]$User, [string]$File) {
    $servers = [ordered]@{}
    $cur = $null
    foreach ($line in ($Text -split "`n")) {
        $l = $line.Trim()
        if ($l -match '^\[') {
            $cur = $null
            if ($l -match '^\[mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))(\.env)?\]') {
                $cur = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
                if (-not $servers.Contains($cur)) { $servers[$cur] = @{ command = ''; args = @(); url = ''; text = '' } }
            }
            continue
        }
        if (-not $cur) { continue }
        $servers[$cur].text += $line + "`n"
        if ($l -match '^command\s*=\s*"([^"]*)"') { $servers[$cur].command = $Matches[1] }
        elseif ($l -match '^url\s*=\s*"([^"]*)"') { $servers[$cur].url = $Matches[1] }
        elseif ($l -match '^args\s*=\s*\[(.*)\]') { $servers[$cur].args = @([regex]::Matches($Matches[1], '"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value }) }
    }
    foreach ($k in $servers.Keys) {
        $s = $servers[$k]
        $m = New-McpServer $Client $User $File $k $s.command $s.args $s.url ''
        $m.secrets = @(Find-SecretsInText $s.text).Count
        $m
    }
}

function Get-AgentConfigs($Profiles) {
    $mcp = @(); $secrets = @(); $errors = @()
    foreach ($p in $Profiles) {
        foreach ($c in $AgentConfigs) {
            $file = @(Resolve-AiPath $c.file $p)[0]
            if (-not $file -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
            $fmt = if ($c.format) { $c.format } else { 'json' }
            try {
                $found = @(); $servers = @()
                if ($fmt -eq 'json') {
                    $j = Read-JsonFile $file ([bool]$c.jsonc)
                    if ($null -eq $j) { continue }
                    if ($c.mcp) { $servers = @(Get-McpFromJson $j $c.mcp $c.client $p.user $file) }
                    foreach ($s in $servers) {
                        $own = @(Find-SecretsInJson $s.json_node $s.json_path)
                        $s.secrets = $own.Count
                        if ($c.scope -ne 'all') { $found += $own }
                        $s.PSObject.Properties.Remove('json_node')
                    }
                    if ($c.scope -eq 'all') { $found = @(Find-SecretsInJson $j '') }
                } else {
                    $t = Read-TextFile $file
                    if ($fmt -eq 'toml') { $servers = @(Get-McpFromToml $t $c.client $p.user $file) }
                    $found = @(Find-SecretsInText $t)
                }
                $mcp += $servers
                foreach ($f in $found) {
                    $secrets += [pscustomobject]@{ client = $c.client; user = $p.user; file = $file; key = $f.key; kind = $f.kind; strong = $f.strong; masked = $f.masked }
                }
            } catch {
                $errors += "$($c.client) config ${file}: $($_.Exception.Message)"
            }
        }
    }
    [pscustomobject]@{ mcp = $mcp; secrets = $secrets; errors = $errors }
}

# --------------------------------------------------------------------------
# known vulnerabilities (OSV.dev)
# --------------------------------------------------------------------------

function Invoke-OsvQuery([string]$Ecosystem, [string]$Name, [string]$Version, [int]$Timeout) {
    $vulns = @(); $tok = $null
    do {
        $q = [ordered]@{ package = [ordered]@{ name = $Name; ecosystem = $Ecosystem }; version = $Version }
        if ($tok) { $q.page_token = $tok }
        $r = Invoke-RestMethod -Uri $OSV_QUERY_URL -Method Post -Body (ConvertTo-Json -InputObject $q -Compress) -ContentType 'application/json' `
            -TimeoutSec $Timeout -UseBasicParsing -UserAgent "vulnagent-local-ai/$VERSION"
        $vulns += @($r.vulns | Where-Object { $_ })
        $tok = $r.next_page_token
    } while ($tok)
    $vulns
}

# CVSS v3.x base score from a vector string
function Get-Cvss3Score([string]$Vector) {
    $m = @{}
    foreach ($p in @($Vector -split '/' | Select-Object -Skip 1)) { $kv = $p -split ':', 2; if ($kv.Count -eq 2) { $m[$kv[0]] = $kv[1] } }
    foreach ($k in 'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A') { if (-not $m.ContainsKey($k)) { return $null } }
    $changed = $m.S -eq 'C'
    $pr = @{ N = 0.85; L = $(if ($changed) { 0.68 } else { 0.62 }); H = $(if ($changed) { 0.5 } else { 0.27 }) }[$m.PR]
    $cia = @{ H = 0.56; L = 0.22; N = 0.0 }
    $av = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.2 }[$m.AV]; $ac = @{ L = 0.77; H = 0.44 }[$m.AC]; $ui = @{ N = 0.85; R = 0.62 }[$m.UI]
    if ($null -eq $pr -or $null -eq $av -or $null -eq $ac -or $null -eq $ui -or -not $cia.ContainsKey($m.C) -or -not $cia.ContainsKey($m.I) -or -not $cia.ContainsKey($m.A)) { return $null }
    $iss = 1 - (1 - $cia[$m.C]) * (1 - $cia[$m.I]) * (1 - $cia[$m.A])
    $impact = if ($changed) { 7.52 * ($iss - 0.029) - 3.25 * [Math]::Pow($iss - 0.02, 15) } else { 6.42 * $iss }
    if ($impact -le 0) { return 0.0 }
    $x = [Math]::Min($(if ($changed) { 1.08 } else { 1 }) * ($impact + 8.22 * $av * $ac * $pr * $ui), 10)
    $i = [long][Math]::Round($x * 100000)
    if ($i % 10000 -eq 0) { return $i / 100000.0 }
    ([Math]::Floor($i / 10000) + 1) / 10.0
}

function Get-OsvSeverity($V) {
    $score = $null
    foreach ($s in @($V.severity)) {
        if ($s -and "$($s.type)" -eq 'CVSS_V3') { $x = Get-Cvss3Score "$($s.score)"; if ($null -ne $x -and ($null -eq $score -or $x -gt $score)) { $score = $x } }
    }
    if ($null -ne $score) {
        $sev = if ($score -ge 9) { 'Critical' } elseif ($score -ge 7) { 'High' } elseif ($score -ge 4) { 'Medium' } else { 'Low' }
        return @{ severity = $sev; score = $score }
    }
    $l = "$(Get-JsonValue $V @('database_specific', 'severity'))".ToUpper()
    $sev = @{ CRITICAL = 'Critical'; HIGH = 'High'; MODERATE = 'Medium'; MEDIUM = 'Medium'; LOW = 'Low' }[$l]
    if (-not $sev) { $sev = 'Medium' }
    @{ severity = $sev; score = $null }
}

# the first version that fixes the vulnerability, above the installed one
function Get-OsvFixed($V, [string]$Name, [string]$Version) {
    $best = ''
    foreach ($a in @($V.affected)) {
        if (-not $a.package -or ("$($a.package.name)" -replace '[-_.]+', '-').ToLower() -ne ($Name -replace '[-_.]+', '-').ToLower()) { continue }
        foreach ($r in @($a.ranges)) {
            if ("$($r.type)" -eq 'GIT') { continue }
            foreach ($e in @($r.events)) {
                $f = "$($e.fixed)"
                if ($f -and (Compare-Version $f $Version) -gt 0 -and (-not $best -or (Compare-Version $f $best) -lt 0)) { $best = $f }
            }
        }
    }
    $best
}

function Get-AiVulnerabilities($Installs, $Cfg, $Errs) {
    $out = @()
    $done = @{}
    foreach ($i in $Installs) {
        if (-not $i.osv_package -or -not $i.version) { continue }
        $key = "$($i.osv_ecosystem)|$($i.osv_package)|$($i.version)"
        if (-not $done.ContainsKey($key)) {
            try {
                $done[$key] = @(Invoke-OsvQuery $i.osv_ecosystem $i.osv_package $i.version 60)
            } catch {
                $Errs.Add("OSV.dev: $($_.Exception.Message)")
                return $out   # offline: don't try the other packages
            }
        }
        $list = @(foreach ($v in $done[$key]) {
            $sv = Get-OsvSeverity $v
            $ids = @(@($v.id) + @($v.aliases) | Where-Object { $_ } | Select-Object -Unique)
            [pscustomobject]@{
                id = "$($v.id)"; cves = @($ids | Where-Object { $_ -like 'CVE-*' }); ids = $ids; severity = $sv.severity; score = $sv.score
                summary = (Get-Clip ("$(if ($v.summary) { $v.summary } else { "$($v.details)".Split("`n")[0] })".Trim()) 200)
                fixed = (Get-OsvFixed $v $i.osv_package $i.version); url = "https://osv.dev/vulnerability/$($v.id)"
            }
        })
        if ($list) { $out += [pscustomobject]@{ install = $i; vulns = $list } }
    }
    $out
}

# --------------------------------------------------------------------------
# findings ("Generic Findings Import" JSON format)
# --------------------------------------------------------------------------

function New-Finding([hashtable]$F) {
    $out = [ordered]@{}
    foreach ($k in 'title', 'severity', 'description', 'mitigation', 'references', 'component_name',
                   'component_version', 'file_path', 'vuln_id_from_tool', 'unique_id_from_tool', 'vulnerability_ids') {
        $v = $F[$k]
        if ($null -eq $v -or ($v -is [string] -and $v -eq '') -or ($v -is [array] -and $v.Count -eq 0)) { continue }
        $out[$k] = $v
    }
    $out['title'] = Get-Clip $out['title'] 500
    $out['static_finding'] = $true
    $out['dynamic_finding'] = $false
    $out['tags'] = $F['tags']
    $out
}

function Get-UserLabel([string]$User) { if ($User) { $User } else { 'no user (process)' } }

function ConvertTo-InventoryFinding($I) {
    $desc = @("**Agent:** $($I.name)$(if ($I.vendor) { " ($($I.vendor))" })", "**Type:** $($I.kind_label)",
              "**Version:** $(if ($I.version) { $I.version } else { 'unknown' })", "**User:** $(Get-UserLabel $I.user)",
              "**Found as:** $($I.source)$(if ($I.detail) { ", $($I.detail)" })", "**Path:** $($I.path)")
    if ($I.running) { $desc += "**Running:** yes (process $(@($I.pids) -join ', '))" }
    New-Finding @{
        title = "AI agent installed: $($I.name)$(if ($I.version) { " $($I.version)" }) ($($I.kind_label), $(Get-UserLabel $I.user))"
        severity = 'Info'; description = ($desc -join "`n")
        mitigation = 'Inventory only. Check that this AI tool is approved for this machine; list the approved ones in ai_allowed to have the others reported.'
        component_name = $I.name; component_version = $I.version; file_path = $I.path
        vuln_id_from_tool = 'ai-inventory'; unique_id_from_tool = 'ai-inventory|{0}|{1}|{2}' -f $I.name, $I.user, $I.path
        tags = @('vulnagent', 'windows', 'ai-agent', 'inventory', $I.kind)
    }
}

function ConvertTo-PolicyFinding($I, [bool]$Blocked, [string]$Severity) {
    $what = if ($Blocked) { 'Blocked AI agent installed' } else { 'AI agent not on the approved list' }
    New-Finding @{
        title = "${what}: $($I.name) ($(Get-UserLabel $I.user))"
        severity = $(if ($Blocked) { 'High' } else { $Severity })
        description = ("**Agent:** $($I.name) $($I.version)`n**Type:** $($I.kind_label)`n**User:** $(Get-UserLabel $I.user)`n**Path:** $($I.path)`n**Policy:** " +
                       $(if ($Blocked) { 'matches ai_blocked in the config' } else { 'not matched by ai_allowed in the config' }))
        mitigation = $(if ($Blocked) { "Uninstall $($I.name) for this user, or remove it from ai_blocked if it is now allowed." }
                       else { "Uninstall $($I.name), or add it to ai_allowed once it is approved." })
        component_name = $I.name; component_version = $I.version; file_path = $I.path
        vuln_id_from_tool = $(if ($Blocked) { 'ai-blocked' } else { 'ai-unapproved' })
        unique_id_from_tool = 'ai-policy|{0}|{1}|{2}' -f $I.name, $I.user, $I.path
        tags = @('vulnagent', 'windows', 'ai-agent', 'policy')
    }
}

function ConvertTo-ExposedFinding($L, $EnvHosts) {
    $desc = @("**Server:** $($L.name)", "**Listens on:** $($L.address) port $($L.port), reachable from other machines unless a firewall blocks the port",
              "**Process:** $($L.process) (process $($L.pid))")
    if ($L.path) { $desc += "**Path:** $($L.path)" }
    if ($L.note) { $desc += "**Note:** $($L.note)" }
    foreach ($e in @($EnvHosts)) { $desc += "**OLLAMA_HOST:** $($e.value) ($(if ($e.user) { "user $($e.user)" } else { 'machine-wide' }))" }
    $desc += '**Risk:** local AI servers have no login by default: anyone who can reach the port can use the models, read what they return and, for some, download or delete models or run tools.'
    $fix = switch ($L.name) {
        'Ollama' { 'Remove the OLLAMA_HOST environment variable (or set it to 127.0.0.1:11434) and restart Ollama. If other machines need it, allow only them in the Windows firewall, or put an authenticating reverse proxy in front.' }
        'LM Studio' { 'Turn off "Serve on Local Network" in LM Studio (Developer tab), or start the server with lms server start without --bind 0.0.0.0.' }
        default { "Make $($L.name) listen on 127.0.0.1 only, or allow only the machines that need it in the Windows firewall." }
    }
    New-Finding @{
        title = "$($L.name) API reachable from the network on port $($L.port)"; severity = 'High'
        description = ($desc -join "`n"); mitigation = $fix
        component_name = $L.name; file_path = $L.path
        vuln_id_from_tool = 'ai-server-exposed'; unique_id_from_tool = 'ai-exposed|{0}|{1}' -f $L.name, $L.port
        tags = @('vulnagent', 'windows', 'ai-agent', 'exposed')
    }
}

function ConvertTo-EnvFinding($E, [string]$Kind) {
    $who = if ($E.user) { "user $($E.user)" } else { 'machine-wide' }
    if ($Kind -eq 'host') {
        New-Finding @{
            title = "Ollama is set to listen on the network (OLLAMA_HOST=$($E.value), $who)"; severity = 'High'
            description = "**Variable:** OLLAMA_HOST=$($E.value)`n**Set:** $who`n**Risk:** when Ollama starts, its API (no login) is reachable from other machines unless a firewall blocks port 11434."
            mitigation = 'Remove OLLAMA_HOST, or set it to 127.0.0.1:11434, then restart Ollama.'
            component_name = 'Ollama'; vuln_id_from_tool = 'ai-ollama-host'; unique_id_from_tool = 'ai-env|OLLAMA_HOST|' + $who
            tags = @('vulnagent', 'windows', 'ai-agent', 'exposed')
        }
    } else {
        New-Finding @{
            title = "Ollama accepts requests from any website (OLLAMA_ORIGINS=$($E.value), $who)"; severity = 'Medium'
            description = "**Variable:** OLLAMA_ORIGINS=$($E.value)`n**Set:** $who`n**Risk:** any web page the user opens can call the local Ollama API from the browser: use the models, list them, or pull and delete models."
            mitigation = 'Remove OLLAMA_ORIGINS, or list only the origins that need access, then restart Ollama.'
            component_name = 'Ollama'; vuln_id_from_tool = 'ai-ollama-origins'; unique_id_from_tool = 'ai-env|OLLAMA_ORIGINS|' + $who
            tags = @('vulnagent', 'windows', 'ai-agent', 'setting')
        }
    }
}

function ConvertTo-ServiceFinding($S) {
    New-Finding @{
        title = "$($S.name) runs as a Windows service under LocalSystem ($($S.service))"; severity = 'Medium'
        description = "**Service:** $($S.display) ($($S.service)), $($S.state)`n**Account:** $(if ($S.account) { $S.account } else { 'LocalSystem' })`n**Command:** $($S.path)`n**Risk:** a flaw in the AI server, or a tool it runs, gives full control of the machine."
        mitigation = 'Run the service under a dedicated low-privilege account (a virtual account such as NT SERVICE\<name>, or a managed service account), with access only to its model folder.'
        component_name = $S.name; vuln_id_from_tool = 'ai-service-system'; unique_id_from_tool = 'ai-service|' + $S.service
        tags = @('vulnagent', 'windows', 'ai-agent', 'service')
    }
}

function ConvertTo-SettingFinding($S) {
    New-Finding @{
        title = "$($S.agent) runs without asking: $($S.setting) ($($S.user))"; severity = $S.severity
        description = "**Agent:** $($S.agent)`n**User:** $($S.user)`n**Setting:** $($S.setting)`n**File:** $($S.file)`n**Risk:** $($S.text)"
        mitigation = $S.fix; component_name = $S.agent; file_path = $S.file
        vuln_id_from_tool = 'ai-auto-approve'; unique_id_from_tool = 'ai-setting|{0}|{1}|{2}' -f $S.agent, $S.file, $S.setting
        tags = @('vulnagent', 'windows', 'ai-agent', 'setting')
    }
}

function ConvertTo-SecretFinding($S) {
    New-Finding @{
        title = "Secret in plain text in the $($S.client) config: $($S.kind) ($($S.user))"
        severity = $(if ($S.strong) { 'High' } else { 'Medium' })
        description = ("**Config:** $($S.client)`n**User:** $($S.user)`n**File:** $($S.file)`n**Where:** $($S.key)`n**Value:** $($S.masked) (only the start is shown)`n" +
                       '**Risk:** AI agents read and quote their configs; a prompt injection, a malicious MCP server or any program running as the user can take the key.')
        mitigation = 'Revoke the key or token and create a new one. Then give it to the tool through an environment variable or the system credential store, referenced in the config (for example "${env:NAME}" in VS Code, or "env" passed through without a value), not written in the file.'
        component_name = $S.client; file_path = $S.file
        vuln_id_from_tool = 'ai-plaintext-secret'; unique_id_from_tool = 'ai-secret|{0}|{1}' -f $S.file, $S.key
        tags = @('vulnagent', 'windows', 'ai-agent', 'secret')
    }
}

function ConvertTo-McpFindings($M, [bool]$Inventory) {
    $desc = @("**MCP server:** $($M.name)", "**Client:** $($M.client)", "**User:** $($M.user)", "**File:** $($M.file)", "**Transport:** $($M.transport)")
    if ($M.command) { $desc += "**Command:** $($M.command)" }
    if ($M.url) { $desc += "**URL:** $($M.url)" }
    $base = 'ai-mcp|{0}|{1}' -f $M.file, $M.name
    if ($Inventory) {
        New-Finding @{
            title = "MCP server configured: $($M.name) in $($M.client) ($($M.user))"; severity = 'Info'; description = ($desc -join "`n")
            mitigation = 'Inventory only. MCP servers run with the rights of the user and their tool output goes to the AI agent: keep only the ones that are needed and trusted.'
            component_name = $M.name; file_path = $M.file; vuln_id_from_tool = 'ai-mcp-server'; unique_id_from_tool = $base
            tags = @('vulnagent', 'windows', 'ai-agent', 'mcp', 'inventory')
        }
    }
    if ($M.package -and $M.pinned -eq $false) {
        New-Finding @{
            title = "MCP server $($M.name) runs an unpinned package: $($M.package) ($($M.client), $($M.user))"; severity = 'Low'
            description = (($desc + "**Risk:** $($M.package) is downloaded at its latest version when the server starts, so a compromised release would run on this machine without anyone installing it.") -join "`n")
            mitigation = "Pin the version in the config, for example $($M.package)@<version> (npx) or $($M.package)==<version> (uvx), and update it on purpose."
            component_name = $M.package; file_path = $M.file; vuln_id_from_tool = 'ai-mcp-unpinned'; unique_id_from_tool = $base + '|unpinned'
            tags = @('vulnagent', 'windows', 'ai-agent', 'mcp')
        }
    }
    if ($M.plain_http) {
        New-Finding @{
            title = "MCP server $($M.name) uses unencrypted HTTP ($($M.client), $($M.user))"; severity = 'Medium'
            description = (($desc + '**Risk:** the requests, tool results and any token in the headers cross the network in clear text.') -join "`n")
            mitigation = 'Use the https:// address of the server, or remove it if it is not needed.'
            component_name = $M.name; file_path = $M.file; vuln_id_from_tool = 'ai-mcp-http'; unique_id_from_tool = $base + '|http'
            tags = @('vulnagent', 'windows', 'ai-agent', 'mcp')
        }
    }
}

function ConvertTo-VulnFinding($V) {
    $i = $V.install
    $order = @($V.vulns | Sort-Object { $SeverityOrder[$_.severity] }, id)
    $sev = $order[0].severity
    $fix = ''
    foreach ($x in $V.vulns) { if ($x.fixed -and (-not $fix -or (Compare-Version $x.fixed $fix) -gt 0)) { $fix = $x.fixed } }
    $names = @($order | ForEach-Object { if ($_.cves) { $_.cves[0] } else { $_.id } })
    $desc = @("**Agent:** $($i.name) $($i.version)", "**User:** $(Get-UserLabel $i.user)", "**Path:** $($i.path)", "**Package:** $($i.osv_package) ($($i.osv_ecosystem))")
    foreach ($x in $order) {
        $desc += "**$($x.severity):** $(if ($x.cves) { $x.cves -join ', ' } else { $x.id }): $($x.summary)$(if ($x.fixed) { " (fixed in $($x.fixed))" })"
    }
    New-Finding @{
        title = "$($i.name) $($i.version) has $(@($V.vulns).Count) known $(if (@($V.vulns).Count -eq 1) { 'vulnerability' } else { 'vulnerabilities' }) ($((@($names | Select-Object -First 3)) -join ', ')$(if ($names.Count -gt 3) { ', ...' }))"
        severity = $sev; description = ($desc -join "`n")
        mitigation = $(if ($fix) { "Update $($i.name) to $fix or later." } else { "No fixed version is listed yet: check the advisories, and remove $($i.name) if it is not needed." })
        references = ((@($order | ForEach-Object { $_.url }) | Select-Object -First 20) -join "`n")
        component_name = $i.name; component_version = $i.version; file_path = $i.path
        vuln_id_from_tool = $order[0].id; unique_id_from_tool = 'ai-vuln|{0}|{1}|{2}' -f $i.osv_package, $i.version, $i.path
        vulnerability_ids = @($V.vulns | ForEach-Object { $_.ids } | Select-Object -Unique)
        tags = @('vulnagent', 'windows', 'ai-agent', 'vulnerability')
    }
}

# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

function Format-Html($Text) { [Net.WebUtility]::HtmlEncode("$Text") }

function Get-FindingKind($Tags) {
    foreach ($k in $FindingKinds.Keys) { if (@($Tags) -contains $k) { return $FindingKinds[$k] } }
    'Other'
}

function ConvertFrom-FindingText([string]$Text) {
    # descriptions are "**Label:** value" lines
    @(foreach ($l in ($Text -split "`n")) { [regex]::Replace((Format-Html $l), '\*\*(.+?)\*\*', '<b>$1</b>') }) -join '<br>'
}

function Get-SevBadge([string]$Severity) {
    '<span class="sev s-' + $Severity.ToLower() + '">' + (Format-Html $Severity) + '</span>'
}

function New-HtmlTable([string[]]$Headers, $Rows, [string]$Empty) {
    if (-not $Rows -or $Rows.Count -eq 0) { return '<p class="none">' + $Empty + '</p>' }
    $head = ($Headers | ForEach-Object { '<th>' + $_ + '</th>' }) -join ''
    $body = ($Rows | ForEach-Object { '<tr>' + (($_ | ForEach-Object { '<td>' + $_ + '</td>' }) -join '') + '</tr>' }) -join "`n"
    '<div class="wrap"><table><thead><tr>' + $head + '</tr></thead><tbody>' + $body + '</tbody></table></div>'
}

$HtmlStyle = @'
body{font:14px/1.45 "Segoe UI",system-ui,sans-serif;background:#fff;color:#1d1d1f;margin:0 auto;padding:24px 16px;max-width:1300px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}h2 small{font-weight:400;color:#666}
.mut,th,.kind,.none{color:#666}.none{font-style:italic}
.cards{display:flex;flex-wrap:wrap;margin:18px -5px 6px}
.card{background:#f4f4f6;border:2px solid transparent;border-radius:8px;padding:8px 16px;margin:5px;min-width:96px;text-align:left;font:inherit;color:inherit}
button.card{cursor:pointer}button.card.on{border-color:#1d1d1f}
.n{display:block;font-size:24px;font-weight:700;line-height:1.2}
.c-critical,.bad{color:#b00020}.c-high,.soon{color:#e65100}.c-medium{color:#b7791f}.c-low{color:#0277bd}.c-info{color:#777}.good{color:#2e7d32}.bad{font-weight:700}
.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;min-width:54px;text-align:center}
.s-critical{background:#b00020}.s-high{background:#e65100}.s-medium{background:#f9a825;color:#1d1d1f}.s-low{background:#0277bd}.s-info{background:#888}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #e3e3e3;padding:6px 8px;text-align:left;vertical-align:top}th{font-weight:600;white-space:nowrap}
.wrap{overflow-x:auto}summary{cursor:pointer}
.desc{margin:6px 0 2px;padding:8px 10px;background:#f4f4f6;border-radius:6px;word-wrap:break-word}
.kind{white-space:nowrap}.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
.bar{display:flex;flex-wrap:wrap;align-items:center;margin:8px 0}.bar>*{margin:0 10px 6px 0}
#q{width:320px;max-width:100%;padding:6px 10px;border:1px solid #bbb;border-radius:6px;font:inherit;background:inherit;color:inherit}
#all{padding:6px 10px;border:1px solid #bbb;border-radius:6px;background:inherit;color:inherit;font:inherit;cursor:pointer}
.warn{border-left:4px solid #e65100;background:#fff4e5;padding:8px 12px;margin:14px 0;border-radius:4px}
.since{border-left:4px solid #0277bd;background:#eef6fb;padding:8px 12px;margin:14px 0;border-radius:4px}.since details{margin-top:4px}
a{color:inherit}ul{margin:4px 0;padding-left:20px}
@media (prefers-color-scheme:dark){body{background:#141416;color:#ececec}.mut,th,.kind,.none,h2 small{color:#9a9a9a}
.card,.desc{background:#1e1e22}th,td{border-color:#2c2c30}button.card.on{border-color:#ececec}.warn{background:#2a2015}.since{background:#15202a}
.c-critical,.bad{color:#ff6b6b}.c-high,.soon{color:#ff9e40}.c-medium{color:#f9c74f}.c-low{color:#4fc3f7}.good{color:#81c784}}
@media print{.bar,#all{display:none}body{max-width:none}}
'@

$HtmlScript = @'
(function () {
  var q = document.getElementById('q'), on = {}, rows = document.querySelectorAll('#findings tbody tr');
  function each(list, fn) { for (var i = 0; i < list.length; i++) fn(list[i]); }
  function apply() {
    var t = q.value.toLowerCase(), any = false, n = 0, k;
    for (k in on) { if (on[k]) any = true; }
    each(rows, function (r) {
      var ok = (!any || on[r.getAttribute('data-sev')]) && (!t || r.textContent.toLowerCase().indexOf(t) >= 0);
      r.style.display = ok ? '' : 'none';
      if (ok) n++;
    });
    document.getElementById('shown').innerHTML = n;
  }
  each(document.querySelectorAll('button.card'), function (c) {
    c.onclick = function () {
      var s = c.getAttribute('data-sev');
      on[s] = !on[s];
      c.className = on[s] ? 'card on' : 'card';
      apply();
    };
  });
  q.oninput = apply; q.onkeyup = apply;
  document.getElementById('all').onclick = function () {
    var d = document.querySelectorAll('#findings details'), o = !(d.length && d[0].open);
    each(d, function (x) { x.open = o; });
  };
  window.onbeforeprint = function () { each(document.querySelectorAll('details'), function (x) { x.open = true; }); };
})();
'@

function ConvertTo-AiHtmlReport($Report, $Doc) {
    $hi = $Report.system
    $all = @($Doc.findings | Sort-Object { $SeverityOrder[$_.severity] }, { $_.title })
    $out = New-Object Collections.Generic.List[string]
    $out.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge">')
    $out.Add('<meta name="viewport" content="width=device-width,initial-scale=1"><title>AI agents - ' + (Format-Html $hi.host) + '</title>')
    $out.Add('<style>' + $HtmlStyle + '</style></head><body>')
    $out.Add('<h1>AI agents &ndash; ' + (Format-Html $hi.host) + '</h1>')
    $meta = @(("$($hi.os) $($hi.version).$($hi.ubr)"), "generated $(([string]$Report.generated).Replace('T', ' '))",
              "$($Report.summary.user_profiles) user profiles checked", $Report.agent)
    $out.Add('<div class="mut">' + (($meta | ForEach-Object { Format-Html $_ }) -join ' &middot; ') + '</div>')
    if ($Report.errors) {
        $out.Add('<div class="warn"><b>Part of the scan failed</b>, so this report may be incomplete:<ul>' +
                 (($Report.errors | ForEach-Object { '<li>' + (Format-Html $_) + '</li>' }) -join '') + '</ul></div>')
    }
    $out.Add((ConvertTo-ChangesHtml $Report.since_last))

    $out.Add('<div class="cards">')
    foreach ($s in $SeverityOrder.Keys) {
        $n = @($all | Where-Object { $_.severity -eq $s }).Count
        $out.Add('<button class="card" data-sev="' + $s + '" title="Show only ' + $s + '"><span class="n c-' + $s.ToLower() + '">' + $n + '</span>' + $s + '</button>')
    }
    $sum = $Report.summary
    $out.Add('<div class="card"><span class="n">' + $sum.agents + '</span>AI agents and tools</div>')
    $out.Add('<div class="card"><span class="n">' + $sum.mcp_servers + '</span>MCP servers</div>')
    $cls = if ($sum.exposed_servers) { ' bad' } else { ' good' }
    $out.Add('<div class="card"><span class="n' + $cls + '">' + $sum.exposed_servers + '</span>AI servers open to the network</div>')
    $cls = if ($sum.secrets) { ' bad' } else { ' good' }
    $out.Add('<div class="card"><span class="n' + $cls + '">' + $sum.secrets + '</span>secrets in plain text</div>')
    $out.Add('</div>')

    $out.Add('<h2 id="findings-title">Findings <small>(<span id="shown">' + $all.Count + '</span> of ' + $all.Count + ' shown)</small></h2>')
    $out.Add('<div class="bar"><input id="q" type="search" placeholder="Search findings, agents, users, CVEs..."><button id="all" type="button">Expand / collapse all</button></div>')
    $rows = foreach ($x in $all) {
        $det = ConvertFrom-FindingText $x.description
        $links = @("$($x.references)" -split "`n" | Where-Object { $_ -match '^https?://' })
        if ($links) { $det += '<br><b>More:</b> ' + (($links | ForEach-Object { '<a href="' + (Format-Html $_) + '">' + (Format-Html $_) + '</a>' }) -join ' ') }
        '<tr data-sev="' + $x.severity + '"><td>' + (Get-SevBadge $x.severity) + '</td><td><details><summary>' + (Format-Html $x.title) +
            '</summary><div class="desc">' + $det + '</div></details></td><td class="kind">' + (Get-FindingKind $x.tags) + '</td><td>' + (Format-Html $x.mitigation) + '</td></tr>'
    }
    if ($all.Count) {
        $out.Add('<div class="wrap"><table id="findings"><thead><tr><th>Severity</th><th>Finding (click for details)</th><th>Type</th><th>What to do</th></tr></thead><tbody>')
        $out.Add(($rows -join "`n"))
        $out.Add('</tbody></table></div>')
    } else {
        $out.Add('<table id="findings"><tbody></tbody></table><p class="none">Nothing found.</p>')
    }

    $rows = New-Object Collections.Generic.List[object]
    foreach ($i in @($Report.agents | Sort-Object kind, name, user)) {
        $rows.Add(@((Format-Html $i.name), (Format-Html $i.version), (Format-Html $i.kind_label), (Format-Html (Get-UserLabel $i.user)),
                    (Format-Html "$($i.source)$(if ($i.detail) { ": $($i.detail)" })"), $(if ($i.running) { '<span class="soon">running</span>' } else { '-' }),
                    ('<span class="mono">' + (Format-Html $i.path) + '</span>')))
    }
    $out.Add('<h2>AI agents and tools <small>(' + $rows.Count + ')</small></h2>')
    $out.Add((New-HtmlTable @('Name', 'Version', 'Type', 'User', 'Found as', 'Now', 'Path') $rows 'None found.'))

    $rows = New-Object Collections.Generic.List[object]
    foreach ($m in @($Report.mcp_servers)) {
        $pin = if ($null -eq $m.pinned) { '-' } elseif ($m.pinned) { '<span class="good">pinned</span>' } else { '<span class="soon">latest</span>' }
        $rows.Add(@((Format-Html $m.name), (Format-Html $m.client), (Format-Html $m.user), (Format-Html $m.transport),
                    ('<span class="mono">' + (Format-Html $(if ($m.url) { $m.url } else { $m.command })) + '</span>'), $pin,
                    $(if ($m.secrets) { '<span class="bad">' + $m.secrets + '</span>' } else { '0' })))
    }
    $out.Add('<h2>MCP servers <small>(' + $rows.Count + ')</small></h2>')
    $out.Add((New-HtmlTable @('Server', 'Client', 'User', 'Transport', 'Command or URL', 'Version', 'Secrets') $rows 'None configured.'))

    $rows = New-Object Collections.Generic.List[object]
    foreach ($l in @($Report.listeners)) {
        $rows.Add(@((Format-Html $l.name), (Format-Html $l.address), [string]$l.port, (Format-Html "$($l.process) ($($l.pid))"),
                    $(if ($l.exposed) { '<span class="bad">yes</span>' } else { '<span class="good">no (this machine only)</span>' })))
    }
    $out.Add('<h2>Local AI servers listening <small>(' + $rows.Count + ')</small></h2>')
    $out.Add((New-HtmlTable @('Server', 'Address', 'Port', 'Process', 'Reachable from the network') $rows 'None running.'))

    $rows = New-Object Collections.Generic.List[object]
    foreach ($s in @($Report.secrets)) {
        $rows.Add(@((Format-Html $s.client), (Format-Html $s.user), (Format-Html $s.kind), (Format-Html $s.key), ('<span class="mono">' + (Format-Html $s.masked) + '</span>'),
                    ('<span class="mono">' + (Format-Html $s.file) + '</span>')))
    }
    $out.Add('<h2>Secrets in agent configs <small>(' + $rows.Count + ')</small></h2>')
    $out.Add((New-HtmlTable @('Config', 'User', 'Kind', 'Where', 'Value (start only)', 'File') $rows 'None found.'))

    $out.Add('<p class="mut" style="margin-top:32px">Full data: ' + (Format-Html (Join-Path $DataDir 'reports\ai.json')) + '; all reports: ' + (Format-Html (Join-Path $DataDir 'reports\index.html')) + '</p>')
    $out.Add('<script>' + $HtmlScript + '</script></body></html>')
    $out -join "`n"
}

# --------------------------------------------------------------------------
# local reports
# --------------------------------------------------------------------------

# ConvertFrom-Json in PowerShell 7 turns dates into [datetime], 5.1 keeps the string
function Format-When($Value) {
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    "$Value".Replace('T', ' ')
}

# what is new and what was fixed since the previous run, by unique_id_from_tool;
# when part of this run failed, a finding that is gone may only not have been checked
function Compare-Findings([string]$PreviousFile, $Findings, [string]$Skip, [bool]$Incomplete) {
    if (-not (Test-Path $PreviousFile)) { return $null }
    try { $prev = Get-Content -Path $PreviousFile -Raw | ConvertFrom-Json } catch { return $null }
    $old = @($prev.findings | Where-Object { $_ -and (-not $Skip -or "$($_.unique_id_from_tool)" -notlike $Skip) })
    $cur = @($Findings | Where-Object { -not $Skip -or "$($_.unique_id_from_tool)" -notlike $Skip })
    $was = @{}; foreach ($f in $old) { $was["$($f.unique_id_from_tool)"] = $true }
    $is = @{}; foreach ($f in $cur) { $is["$($f.unique_id_from_tool)"] = $true }
    [ordered]@{
        previous = (Get-Item $PreviousFile).LastWriteTime.ToString('s'); incomplete = $Incomplete
        new      = @($cur | Where-Object { -not $was.ContainsKey("$($_.unique_id_from_tool)") } | ForEach-Object { [ordered]@{ severity = $_.severity; title = $_.title } })
        fixed    = @($old | Where-Object { -not $is.ContainsKey("$($_.unique_id_from_tool)") } | ForEach-Object { [ordered]@{ severity = $_.severity; title = $_.title } })
    }
}

function ConvertTo-ChangesHtml($Since) {
    if (-not $Since) { return '<div class="since">First report on this machine: the next one shows what changed since this run.</div>' }
    $gone = if ($Since.incomplete) { 'Gone, but part of this run failed, so some may not be fixed' } else { 'Fixed' }
    $parts = foreach ($p in @(@('New', $Since.new), @($gone, $Since.fixed))) {
        if (@($p[1]).Count) {
            '<details><summary>' + $p[0] + ' (' + @($p[1]).Count + ')</summary><ul>' +
                ((@($p[1]) | ForEach-Object { '<li><span class="sev s-' + "$($_.severity)".ToLower() + '">' + (Format-Html $_.severity) + '</span> ' + (Format-Html $_.title) + '</li>' }) -join '') +
                '</ul></details>'
        }
    }
    '<div class="since"><b>Since the last run</b> (' + (Format-Html (Format-When $Since.previous)) + '): ' +
        @($Since.new).Count + ' new, ' + @($Since.fixed).Count + $(if ($Since.incomplete) { ' gone (part of this run failed).' } else { ' fixed.' }) +
        ($parts -join '') + '</div>'
}

# <kind>.html, <kind>.json and <kind>-findings.json are the latest run; history keeps a dated copy of each run
function Save-Reports([string]$Kind, $Report, $Doc, [string]$Page, $Cfg, $Counts) {
    $dir = Join-Path $DataDir 'reports'
    $hist = Join-Path $dir 'history'
    New-Item -ItemType Directory -Force -Path $hist | Out-Null
    Write-JsonFile (Join-Path $dir "$Kind.json") $Report
    Write-JsonFile (Join-Path $dir "$Kind-findings.json") $Doc
    $stamp = '{0}-{1}' -f ([datetime]$Report.generated).ToString('yyyyMMdd-HHmmss'), $Kind
    if ($Page) {
        Write-TextFile (Join-Path $dir "$Kind.html") $Page
        Write-TextFile (Join-Path $hist "$stamp.html") $Page
    }
    $since = $Report.since_last
    Write-JsonFile (Join-Path $hist "$stamp.json") ([ordered]@{
        kind = $Kind; generated = $Report.generated; host = $Report.host; agent = $Report.agent
        description = $Doc.description; severities = $Counts; score = $Report.summary.score
        new = $(if ($since) { @($since.new).Count } else { $null }); fixed = $(if ($since) { @($since.fixed).Count } else { $null })
        errors = @($Report.errors).Count; html = $(if ($Page) { "history/$stamp.html" } else { $null })
    })
    $days = [int]$Cfg.keep_reports_days
    if ($days -gt 0) {
        $limit = (Get-Date).AddDays(-$days)
        Get-ChildItem -Path $hist -File | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    # the scan, the hardening check and the AI agent scan all rewrite the index; if they collide, the next run fixes it
    try { Update-ReportIndex } catch { Write-Log "ERROR report index: $($_.Exception.Message)" }
}

function Update-ReportIndex {
    $dir = Join-Path $DataDir 'reports'
    $runs = @(foreach ($f in @(Get-ChildItem -Path (Join-Path $dir 'history') -Filter '*.json' -File | Sort-Object Name -Descending)) {
        try { Get-Content -Path $f.FullName -Raw | ConvertFrom-Json } catch { }
    })
    $name = if ($runs.Count) { $runs[0].host } else { $env:COMPUTERNAME }
    $out = New-Object Collections.Generic.List[string]
    $out.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge">')
    $out.Add('<meta name="viewport" content="width=device-width,initial-scale=1"><title>Reports - ' + (Format-Html $name) + '</title>')
    $out.Add('<style>' + $HtmlStyle + 'a.card{text-decoration:none}</style></head><body>')
    $out.Add('<h1>Security reports &ndash; ' + (Format-Html $name) + '</h1>')
    $out.Add('<div class="mut">vulnagent-local: these reports stay on this machine, in ' + (Format-Html $dir) + '. Updated ' + (Get-Date).ToString('yyyy-MM-dd HH:mm') + '.</div>')
    $out.Add('<div class="cards">')
    foreach ($k in @(@('scan', 'Latest scan'), @('hardening', 'Latest hardening check'), @('ai', 'Latest AI agent scan'))) {
        $last = @($runs | Where-Object { $_.kind -eq $k[0] }) | Select-Object -First 1
        if (-not $last -or -not (Test-Path (Join-Path $dir "$($k[0]).html"))) { continue }
        $big = if ($k[0] -eq 'hardening') { "$($last.score)%" } else { [string](@($last.severities.PSObject.Properties | ForEach-Object { [int]$_.Value }) | Measure-Object -Sum).Sum }
        $what = if ($k[0] -eq 'hardening') { 'compliant' } else { 'findings' }
        $out.Add('<a class="card" href="' + $k[0] + '.html"><span class="n">' + $big + '</span>' + $what + ' &middot; ' + $k[1] + ', ' +
                 (Format-Html (Format-When $last.generated)) + '</a>')
    }
    $out.Add('</div>')
    $out.Add('<h2>All reports <small>(' + $runs.Count + ')</small></h2>')
    if ($runs.Count) {
        $out.Add('<div class="wrap"><table><thead><tr><th>When</th><th>Report</th><th>Result</th>' +
                 (($SeverityOrder.Keys | ForEach-Object { '<th>' + $_ + '</th>' }) -join '') + '<th>New</th><th>Fixed</th></tr></thead><tbody>')
        foreach ($r in $runs) {
            $label = @{ hardening = 'Hardening'; ai = 'AI agents' }["$($r.kind)"]
            if (-not $label) { $label = 'Scan' }
            if ($r.html -and (Test-Path (Join-Path $dir $r.html))) { $label = '<a href="' + (Format-Html $r.html) + '">' + $label + '</a>' }
            $total = @($r.severities.PSObject.Properties | ForEach-Object { [int]$_.Value }) | Measure-Object -Sum
            $result = if ($r.kind -eq 'hardening') { "$($r.score)% compliant, $($total.Sum) failed" } else { "$($total.Sum) findings" }
            if ($r.errors) { $result += ' (incomplete)' }
            $cells = foreach ($s in $SeverityOrder.Keys) {
                $n = [int]$r.severities.$s
                '<td' + $(if ($n) { ' class="c-' + $s.ToLower() + '"' } else { '' }) + '>' + $n + '</td>'
            }
            $out.Add('<tr><td>' + (Format-Html (Format-When $r.generated)) + '</td><td>' + $label + '</td><td>' + (Format-Html $result) + '</td>' +
                     ($cells -join '') + '<td>' + $(if ($null -ne $r.new) { $r.new } else { '-' }) + '</td><td>' + $(if ($null -ne $r.fixed) { $r.fixed } else { '-' }) + '</td></tr>')
        }
        $out.Add('</tbody></table></div>')
    } else {
        $out.Add('<p class="none">No reports yet.</p>')
    }
    Write-TextFile (Join-Path $dir 'index.html') ($out -join "`n")
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

function Test-Ignored($F, $Cfg) {
    foreach ($p in @($Cfg.ai_ignore)) {
        if (-not $p) { continue }
        if ("$($F.component_name)" -like $p -or "$($F.vuln_id_from_tool)" -like $p -or "$($F.unique_id_from_tool)" -like $p) { return $true }
    }
    $false
}

function Invoke-Main {
    try {
        Initialize-DataDir
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072  # TLS 1.2
        $cfg = Read-Config $ConfigPath
        $today = Get-Date
        $errs = New-Object Collections.Generic.List[string]
        $hi = Get-HostInfo
        Write-Log "vulnagent-local-ai $VERSION on $($hi.host): $($hi.os) $($hi.version).$($hi.ubr)"

        $profiles = @(Get-UserProfiles)
        Write-Log "  $($profiles.Count) user profiles: $((@($profiles | ForEach-Object { $_.user })) -join ', ')"

        # 1. what is installed and running
        $installs = @()
        try { $installs = @(Find-AiInstalls $profiles) } catch { $errs.Add('AI agents: ' + $_.Exception.Message) }
        try { $installs += @(Find-AiRegistered $installs $profiles) } catch { $errs.Add('installed programs: ' + $_.Exception.Message) }
        $runtime = $null
        try {
            $runtime = Get-AiRuntime $installs
            $installs += @($runtime.extra)
        } catch { $errs.Add('processes and ports: ' + $_.Exception.Message) }
        $listeners = if ($runtime) { @($runtime.listeners) } else { @() }
        $services = if ($runtime) { @($runtime.services) } else { @() }
        Write-Log "  $($installs.Count) AI agents and tools, $(@($installs | Where-Object { $_.running }).Count) running"
        foreach ($i in $installs) { Write-Log "    $($i.name) $($i.version) ($($i.kind_label), $(Get-UserLabel $i.user))" }

        # 2. settings, MCP servers and secrets
        $settings = @()
        try { $settings = @(Get-AgentSettingIssues $profiles) } catch { $errs.Add('agent settings: ' + $_.Exception.Message) }
        $mcp = @(); $secrets = @()
        try {
            $conf = Get-AgentConfigs $profiles
            $mcp = @($conf.mcp); $secrets = @($conf.secrets)
            foreach ($e in @($conf.errors)) { $errs.Add($e) }
        } catch { $errs.Add('agent configs: ' + $_.Exception.Message) }
        $ollamaHost = @(); $ollamaOrigins = @()
        try {
            $ollamaHost = @(Get-EnvValues 'OLLAMA_HOST' $profiles | Where-Object { -not (Test-LoopbackHost (Get-BindHost $_.value)) })
            $ollamaOrigins = @(Get-EnvValues 'OLLAMA_ORIGINS' $profiles | Where-Object { $_.value -split ',' | Where-Object { $_.Trim() -eq '*' } })
        } catch { $errs.Add('environment variables: ' + $_.Exception.Message) }
        Write-Log "  $($mcp.Count) MCP servers, $($secrets.Count) secrets in plain text, $($settings.Count) risky settings"

        # 3. known vulnerabilities
        $vulns = @()
        if ($cfg.ai_osv) {
            $vulns = @(Get-AiVulnerabilities $installs $cfg $errs)
            Write-Log "  OSV.dev: $($vulns.Count) agents with known vulnerabilities"
        }

        # 4. findings
        $findings = New-Object Collections.Generic.List[object]
        $exposed = @($listeners | Where-Object { $_.exposed })
        foreach ($l in @($exposed | Sort-Object name, port -Unique)) {
            $findings.Add((ConvertTo-ExposedFinding $l $(if ($l.name -eq 'Ollama') { $ollamaHost } else { @() })))
        }
        if (-not @($exposed | Where-Object { $_.name -eq 'Ollama' })) { foreach ($e in $ollamaHost) { $findings.Add((ConvertTo-EnvFinding $e 'host')) } }
        foreach ($e in $ollamaOrigins) { $findings.Add((ConvertTo-EnvFinding $e 'origins')) }
        foreach ($s in @($services | Where-Object { $_.system })) { $findings.Add((ConvertTo-ServiceFinding $s)) }
        foreach ($s in $settings) { $findings.Add((ConvertTo-SettingFinding $s)) }
        foreach ($s in $secrets) { $findings.Add((ConvertTo-SecretFinding $s)) }
        foreach ($v in $vulns) { $findings.Add((ConvertTo-VulnFinding $v)) }
        foreach ($m in $mcp) { foreach ($f in @(ConvertTo-McpFindings $m ([bool]$cfg.ai_inventory))) { if ($f) { $findings.Add($f) } } }
        foreach ($i in $installs) {
            if (Test-NameMatch $i.name $cfg.ai_blocked) { $findings.Add((ConvertTo-PolicyFinding $i $true 'High')) }
            elseif (@($cfg.ai_allowed | Where-Object { $_ }).Count -and -not (Test-NameMatch $i.name $cfg.ai_allowed)) {
                $sev = if ($SeverityOrder.Contains("$($cfg.ai_unapproved_severity)")) { "$($cfg.ai_unapproved_severity)" } else { 'Medium' }
                $findings.Add((ConvertTo-PolicyFinding $i $false $sev))
            }
            if ($cfg.ai_inventory) { $findings.Add((ConvertTo-InventoryFinding $i)) }
        }
        $kept = @($findings | Where-Object { -not (Test-Ignored $_ $cfg) })
        $findings = New-Object Collections.Generic.List[object]
        foreach ($f in $kept) { $findings.Add($f) }
        foreach ($e in $errs) { Write-Log "ERROR $e" }

        # 5. reports
        $since = Compare-Findings (Join-Path $DataDir 'reports\ai-findings.json') $findings $null ($errs.Count -gt 0)
        $doc = [ordered]@{
            name = 'vulnagent-local-ai'; type = $SCAN_TYPE; version = $VERSION
            description = '{0} - {1} AI agents and tools, {2} MCP servers, {3} AI servers open to the network, {4} secrets in plain text' -f `
                $hi.host, $installs.Count, $mcp.Count, @($exposed | Sort-Object name, port -Unique).Count, $secrets.Count
            findings = $findings.ToArray()
        }
        $report = [ordered]@{
            agent = "vulnagent-local-ai $VERSION"; generated = $today.ToString('s'); host = $hi.host; system = $hi
            errors = $errs.ToArray(); since_last = $since
            profiles = @($profiles | ForEach-Object { $_.user })
            agents = $installs; mcp_servers = $mcp; listeners = $listeners; services = $services; settings = $settings
            secrets = $secrets
            vulnerabilities = @($vulns | ForEach-Object { [ordered]@{ agent = $_.install.name; version = $_.install.version; user = $_.install.user; path = $_.install.path; vulns = $_.vulns } })
            summary = [ordered]@{ findings = $findings.Count; user_profiles = $profiles.Count; agents = $installs.Count
                                  running = @($installs | Where-Object { $_.running }).Count; mcp_servers = $mcp.Count
                                  exposed_servers = @($exposed | Sort-Object name, port -Unique).Count; secrets = $secrets.Count
                                  risky_settings = $settings.Count; vulnerable_agents = $vulns.Count }
        }
        if ($Output) { Write-JsonFile $Output $doc; Write-Log "wrote $Output" }
        $page = $null
        try { $page = ConvertTo-AiHtmlReport $report $doc } catch { Write-Log "ERROR HTML report: $($_.Exception.Message)" }
        $counts = [ordered]@{}
        foreach ($s in $SeverityOrder.Keys) { $counts[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }
        Save-Reports 'ai' $report $doc $page $cfg $counts
        if ($Html -and $page) {
            $Html = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Html)
            Write-TextFile $Html $page
            Write-Log "HTML report: $Html"
        }
        $bySev = foreach ($s in $counts.Keys) { if ($counts[$s]) { "$s $($counts[$s])" } }
        Write-Log ("{0} findings: {1}" -f $findings.Count, $(if ($bySev) { $bySev -join ', ' } else { 'none' }))
        if ($since) { Write-Log ("since the last run: {0} new, {1} {2}" -f @($since.new).Count, @($since.fixed).Count, $(if ($since.incomplete) { 'gone (part of the scan failed)' } else { 'fixed' })) }
        Write-Log "report: $(Join-Path $DataDir 'reports\ai.html')"
        if ($errs.Count) { return 2 }
        return 0
    } catch {
        Write-Log "ERROR $($_.Exception.Message)"
        return 3
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit [int]@(Invoke-Main)[-1] }
