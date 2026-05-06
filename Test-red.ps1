#Requires -Version 5.1
<#
.SYNOPSIS
    Descubrimiento de red sin privilegios de administrador
    Pasivo primero, ping solo donde sea necesario, verificacion de 6 puertos

.PARAMETER OutputPath  Carpeta de salida (default: .)
.PARAMETER Timeout     Timeout ms (default 500)
.PARAMETER PingSweep   Hacer ping sweep despues de recoleccion pasiva (default: true)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [int]   $Timeout    = 500,
    [bool]  $PingSweep  = $true
)

if ((Get-ExecutionPolicy -Scope Process) -in @("Restricted","AllSigned")) {
    $self = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$self`"" -NoNewWindow -Wait
    exit
}

#region -- CONSOLA -----------------------------------------------------------

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host "  |  DESCUBRIMIENTO DE RED - SIN PRIVILEGIOS ADMIN      |" -ForegroundColor Cyan
    Write-Host "  |  Pasivo + Ping + Verificacion FTP/SSH/Telnet/HTTP/   |" -ForegroundColor Cyan
    Write-Host "  |  HTTPS/SMB                                           |" -ForegroundColor Cyan
    Write-Host "  +======================================================+" -ForegroundColor Cyan
    Write-Host "  [!] Solo usar con autorizacion escrita" -ForegroundColor Yellow
    Write-Host ""
}

function Write-Step([string]$Num, [string]$Msg) {
    Write-Host ""
    Write-Host "  [$Num] $Msg" -ForegroundColor Cyan
    Write-Host "  $('-'*55)" -ForegroundColor DarkCyan
}

function Write-Found([string]$IP, [string]$Source, [string]$Extra = "") {
    Write-Host ("    {0,-18} {1,-20} {2}" -f $IP, $Source, $Extra) -ForegroundColor Yellow
}

function Write-Info([string]$Msg) {
    Write-Host "  $Msg" -ForegroundColor Gray
}

#endregion

#region -- UTILIDADES DE RED -------------------------------------------------

function Get-NetworkAddress([string]$IP, [int]$Prefix) {
    $o = $IP -split "\."
    $n = ([int64]$o[0] -shl 24)+([int64]$o[1] -shl 16)+([int64]$o[2] -shl 8)+[int64]$o[3]
    $m = ([int64]0xFFFFFFFF)-([int64][math]::Pow(2,32-$Prefix)-1)
    $r = $n -band $m
    "{0}.{1}.{2}.{3}" -f (($r -shr 24) -band 255),(($r -shr 16) -band 255),(($r -shr 8) -band 255),($r -band 255)
}

function Get-SubnetIPs([string]$Network, [int]$Prefix) {
    $o = $Network -split "\."
    $b = ([int64]$o[0] -shl 24)+([int64]$o[1] -shl 16)+([int64]$o[2] -shl 8)+[int64]$o[3]
    $c = [int][math]::Min([math]::Pow(2,32-$Prefix)-2, 254)
    1..$c | ForEach-Object {
        $x = $b+$_
        "{0}.{1}.{2}.{3}" -f (($x -shr 24) -band 255),(($x -shr 16) -band 255),(($x -shr 8) -band 255),($x -band 255)
    }
}

function IsValid([string]$IP) {
    if (-not $IP -or $IP -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") { return $false }
    if ($IP -match "^(0\.|127\.|169\.254\.|224\.|239\.|255\.)") { return $false }
    $last = [int]($IP -split "\.")[-1]
    return ($last -ne 0 -and $last -ne 255)
}

function GetSubnet([string]$IP, [PSCustomObject[]]$Adapters) {
    $p = $IP -split "\."
    if ($p.Count -ne 4) { return "?" }
    $ipInt = ([int64]$p[0] -shl 24)+([int64]$p[1] -shl 16)+([int64]$p[2] -shl 8)+[int64]$p[3]
    foreach ($a in $Adapters) {
        $n = $a.Network -split "\."
        $nInt = ([int64]$n[0] -shl 24)+([int64]$n[1] -shl 16)+([int64]$n[2] -shl 8)+[int64]$n[3]
        $mask = ([int64]0xFFFFFFFF)-([int64][math]::Pow(2,32-$a.Prefix)-1)
        if (($ipInt -band $mask) -eq ($nInt -band $mask)) { return $a.Subnet }
    }
    return "Otra"
}

#endregion

#region -- RECOLECCION PASIVA ------------------------------------------------

function Add-Host {
    param($Dict, [string]$IP, [string]$Source, [string[]]$MyIPs)
    if (-not (IsValid $IP)) { return }
    if ($IP -in $MyIPs) { return }
    if (-not $Dict.ContainsKey($IP)) {
        $Dict[$IP] = [PSCustomObject]@{ IP=$IP; Sources=[System.Collections.Generic.List[string]]::new(); MAC="" }
    }
    if ($Source -notin $Dict[$IP].Sources) { $Dict[$IP].Sources.Add($Source) }
}

function Invoke-PassiveCollection {
    param([string[]]$MyIPs, [PSCustomObject[]]$Adapters)

    $found = [System.Collections.Generic.Dictionary[string,PSCustomObject]]::new()

    # 1. ARP cache - encoding IBM850 para Windows en espanol
    $prev = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(850) } catch {}
    $arpLines = @(arp -a 2>&1)
    try { [Console]::OutputEncoding = $prev } catch {}

    foreach ($line in $arpLines) {
        if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})") {
            $ip  = $matches[1]
            $mac = $matches[2].ToUpper()
            if ($mac -match "^(FF-FF|01-00-5E)") { continue }
            Add-Host $found $ip "ARP" $MyIPs
            if ($found.ContainsKey($ip) -and -not $found[$ip].MAC) { $found[$ip].MAC = $mac }
        }
    }
    Write-Info "ARP cache:           $($found.Count) hosts"

    # 2. Conexiones TCP activas (Get-NetTCPConnection)
    $before = $found.Count
    Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Host $found $_.RemoteAddress "TCPConn" $MyIPs
        Add-Host $found $_.LocalAddress  "TCPLocal" $MyIPs
    }
    Write-Info "Conexiones TCP:      +$($found.Count - $before) hosts nuevos"

    # 3. netstat -n
    $before = $found.Count
    netstat -n 2>$null | ForEach-Object {
        $cols = $_ -split "\s+" | Where-Object { $_ -match "\d+\.\d+\.\d+\.\d+" }
        foreach ($col in $cols) {
            $ip = ($col -split ":")[0]
            Add-Host $found $ip "netstat" $MyIPs
        }
    }
    Write-Info "netstat:             +$($found.Count - $before) hosts nuevos"

    # 4. DNS cache - puede revelar IPs de segmentos internos
    $before = $found.Count
    ipconfig /displaydns 2>$null | ForEach-Object {
        if ($_ -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
            Add-Host $found $matches[1] "DNSCache" $MyIPs
        }
    }
    Write-Info "DNS cache:           +$($found.Count - $before) hosts nuevos"

    # 5. Tabla de rutas - revela gateways y segmentos conocidos
    $before = $found.Count
    route print 2>$null | ForEach-Object {
        if ($_ -match "^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
            Add-Host $found $matches[2] "Route-GW" $MyIPs  # gateway
        }
    }
    Write-Info "Tabla de rutas:      +$($found.Count - $before) hosts nuevos"

    return $found
}

#endregion

#region -- PING SWEEP ASINCRONO ----------------------------------------------

function Invoke-PingSweep {
    param([string[]]$IPs, [int]$Ms)

    $tasks = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($ip in $IPs) {
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $tasks.Add(@{ IP=$ip; Ping=$ping; Task=$ping.SendPingAsync($ip, $Ms) })
        } catch {}
    }

    $total = $tasks.Count
    while (@($tasks | Where-Object { -not $_.Task.IsCompleted }).Count -gt 0) {
        $done = @($tasks | Where-Object { $_.Task.IsCompleted }).Count
        Write-Host "`r  Ping: $done/$total ($(([math]::Round($done/$total*100)))%)   " -NoNewline -ForegroundColor Gray
        Start-Sleep -Milliseconds 100
    }
    Write-Host "`r  Ping: $total/$total (100%) completado                " -ForegroundColor Gray

    $alive = @()
    foreach ($t in $tasks) {
        try { if ($t.Task.Result.Status -eq "Success") { $alive += $t.IP } } catch {}
        try { $t.Ping.Dispose() } catch {}
    }
    return $alive
}

#endregion

#region -- VERIFICACION DE PUERTOS -------------------------------------------

$Ports = @(
    @{Port=21;  Name="FTP"   }
    @{Port=22;  Name="SSH"   }
    @{Port=23;  Name="Telnet"}
    @{Port=80;  Name="HTTP"  }
    @{Port=443; Name="HTTPS" }
    @{Port=445; Name="SMB"   }
)

function Test-Host([string]$IP, [int]$Ms) {
    $r = [PSCustomObject]@{ IP=$IP; ICMP=$false; Open=@() }

    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $r.ICMP = ($p.Send($IP, $Ms).Status -eq "Success")
    } catch {}

    foreach ($p in $Ports) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar  = $tcp.BeginConnect($IP, $p.Port, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne($Ms, $false)
            if ($ok -and $tcp.Connected) { $r.Open += "$($p.Name)($($p.Port))" }
            try { $tcp.Close() } catch {}
        } catch {}
    }
    return $r
}

#endregion

#region -- MOTOR PRINCIPAL ---------------------------------------------------

function Invoke-Main {
    param([int]$Ms, [bool]$DoPing)

    # Detectar mis adaptadores
    $adapters = [System.Collections.Generic.List[PSCustomObject]]::new()
    $myIPs    = [System.Collections.Generic.List[string]]::new()
    $mySubnets= [System.Collections.Generic.HashSet[string]]::new()

    foreach ($adapter in (Get-NetAdapter | Where-Object Status -eq "Up")) {
        $info = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254\.)" }
        if (-not $info) { continue }
        $net = Get-NetworkAddress $info.IPAddress $info.PrefixLength
        $gw  = (Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
                Where-Object DestinationPrefix -eq "0.0.0.0/0" | Select-Object -First 1).NextHop
        $a = [PSCustomObject]@{
            Name=  $adapter.Name; IP=$info.IPAddress
            Prefix=$info.PrefixLength; Network=$net
            Subnet="$net/$($info.PrefixLength)"; Gateway=$gw
        }
        [void]$adapters.Add($a)
        [void]$myIPs.Add($info.IPAddress)
        [void]$mySubnets.Add($a.Subnet)
    }

    # ==========================================================
    Write-Step "1" "MI POSICION EN LA RED"
    # ==========================================================
    Write-Host ""
    foreach ($a in $adapters) {
        Write-Host "  Adaptador : $($a.Name)" -ForegroundColor White
        Write-Host "  IP        : $($a.IP)/$($a.Prefix)   Subred: $($a.Subnet)   GW: $(if($a.Gateway){$a.Gateway}else{'?'})" -ForegroundColor Cyan
        Write-Host ""
    }

    # ==========================================================
    Write-Step "2" "RECOLECCION PASIVA (sin generar trafico)"
    # ==========================================================
    Write-Host ""
    $hosts = Invoke-PassiveCollection -MyIPs @($myIPs) -Adapters @($adapters)
    Write-Host ""
    Write-Info "Total pasivo: $($hosts.Count) IPs unicas descubiertas"

    # ==========================================================
    Write-Step "3" "PING SWEEP (pobla ARP, descubre mas hosts)"
    # ==========================================================
    if ($DoPing) {
        # Construir lista de IPs que AUN no hemos visto
        $allSubnetIPs = [System.Collections.Generic.List[string]]::new()
        foreach ($a in $adapters) {
            Get-SubnetIPs $a.Network $a.Prefix | ForEach-Object {
                if (-not $hosts.ContainsKey($_) -and $_ -notin $myIPs) {
                    [void]$allSubnetIPs.Add($_)
                }
            }
        }

        Write-Host ""
        Write-Info "IPs pendientes de ping: $($allSubnetIPs.Count)"

        if ($allSubnetIPs.Count -gt 0) {
            $icmpAlive = Invoke-PingSweep -IPs @($allSubnetIPs) -Ms ([math]::Min($Ms, 400))

            # Reler ARP despues del sweep
            Start-Sleep -Milliseconds 800
            $prev = [Console]::OutputEncoding
            try { [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(850) } catch {}
            $arpLines = @(arp -a 2>&1)
            try { [Console]::OutputEncoding = $prev } catch {}

            foreach ($line in $arpLines) {
                if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})") {
                    $ip = $matches[1]; $mac = $matches[2].ToUpper()
                    if ($mac -match "^(FF-FF|01-00-5E)") { continue }
                    if (-not (IsValid $ip) -or $ip -in $myIPs) { continue }
                    if (-not $hosts.ContainsKey($ip)) {
                        $hosts[$ip] = [PSCustomObject]@{ IP=$ip; Sources=[System.Collections.Generic.List[string]]::new(); MAC=$mac }
                        $hosts[$ip].Sources.Add("ARP-post-ping")
                    }
                    if (-not $hosts[$ip].MAC) { $hosts[$ip].MAC = $mac }
                }
            }

            # Agregar los que respondieron ICMP directamente
            foreach ($ip in $icmpAlive) {
                if (-not (IsValid $ip) -or $ip -in $myIPs) { continue }
                if (-not $hosts.ContainsKey($ip)) {
                    $hosts[$ip] = [PSCustomObject]@{ IP=$ip; Sources=[System.Collections.Generic.List[string]]::new(); MAC="via-ICMP" }
                    $hosts[$ip].Sources.Add("ICMP")
                }
            }
            Write-Info "Nuevos tras ping sweep: $($icmpAlive.Count) ICMP"
        }
    }

    Write-Host ""
    Write-Info "TOTAL hosts descubiertos: $($hosts.Count)"

    # Clasificar: mi red vs otras subredes
    $myNet    = @{}
    $otherNet = @{}
    foreach ($ip in $hosts.Keys) {
        $sub = GetSubnet $ip @($adapters)
        $hosts[$ip] | Add-Member -NotePropertyName Subnet -NotePropertyValue $sub -Force
        if ($sub -in $mySubnets) { $myNet[$ip]    = $hosts[$ip] }
        else                     { $otherNet[$ip] = $hosts[$ip] }
    }

    # Mostrar todos los hosts encontrados
    Write-Host ""
    Write-Host ("  {0,-18} {1,-25} {2,-20} {3}" -f "IP","Subred","MAC","Fuente") -ForegroundColor Gray
    Write-Host "  $('-'*80)" -ForegroundColor Gray
    foreach ($ip in ($hosts.Keys | Sort-Object { $p=$_ -split "\."; [int64]$p[0]*16777216+[int64]$p[1]*65536+[int64]$p[2]*256+[int64]$p[3] })) {
        $h   = $hosts[$ip]
        $col = if ($otherNet.ContainsKey($ip)) { "Yellow" } else { "White" }
        $tag = if ($otherNet.ContainsKey($ip)) { " << OTRA SUBRED" } else { "" }
        Write-Host ("  {0,-18} {1,-25} {2,-20} {3}{4}" -f $ip, $h.Subnet, $h.MAC, ($h.Sources -join "/"), $tag) -ForegroundColor $col
    }

    # ==========================================================
    Write-Step "4" "VERIFICACION DE 6 PUERTOS EN HOSTS DESCUBIERTOS"
    # ==========================================================
    Write-Host ""
    Write-Info "Verificando ICMP + FTP/SSH/Telnet/HTTP/HTTPS/SMB en $($hosts.Count) hosts..."
    Write-Host ""

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sorted  = @($hosts.Keys | Sort-Object { $p=$_ -split "\."; [int64]$p[0]*16777216+[int64]$p[1]*65536+[int64]$p[2]*256+[int64]$p[3] })
    $i = 0
    foreach ($ip in $sorted) {
        $i++
        Write-Host "`r  $i/$($sorted.Count) : $ip                          " -NoNewline -ForegroundColor Gray
        [void]$results.Add((Test-Host $ip $Ms))
    }
    Write-Host "`r  $($sorted.Count)/$($sorted.Count) completado                              " -ForegroundColor Green
    Write-Host ""

    # Tabla de resultados
    Write-Host ("  {0,-18} {1,-6} {2,-5} {3,-5} {4,-8} {5,-6} {6,-7} {7,-5} {8}" -f "IP","ICMP","FTP","SSH","Telnet","HTTP","HTTPS","SMB","Subred") -ForegroundColor Gray
    Write-Host "  $('-'*80)" -ForegroundColor Gray

    foreach ($r in $results) {
        $hasAny = $r.ICMP -or $r.Open.Count -gt 0
        if (-not $hasAny) { continue }
        $inOther = $otherNet.ContainsKey($r.IP)
        $col  = if ($inOther) { "Yellow" } else { "White" }
        $tag  = if ($inOther) { " <<" } else { "" }
        $sub  = GetSubnet $r.IP @($adapters)
        $ic   = if ($r.ICMP) { "SI" } else { "--" }
        $ftp  = if ("FTP(21)"    -in $r.Open) { "OPEN" } else { "----" }
        $ssh  = if ("SSH(22)"    -in $r.Open) { "OPEN" } else { "----" }
        $tel  = if ("Telnet(23)" -in $r.Open) { "OPEN" } else { "----" }
        $http = if ("HTTP(80)"   -in $r.Open) { "OPEN" } else { "----" }
        $htts = if ("HTTPS(443)" -in $r.Open) { "OPEN" } else { "----" }
        $smb  = if ("SMB(445)"   -in $r.Open) { "OPEN" } else { "----" }
        Write-Host ("  {0,-18} {1,-6} {2,-5} {3,-5} {4,-8} {5,-6} {6,-7} {7,-5} {8}{9}" -f $r.IP,$ic,$ftp,$ssh,$tel,$http,$htts,$smb,$sub,$tag) -ForegroundColor $col
    }

    # ==========================================================
    Write-Step "5" "RESUMEN"
    # ==========================================================
    $conAlgo  = @($results | Where-Object { $_.ICMP -or $_.Open.Count -gt 0 })
    $otrasAct = @($conAlgo  | Where-Object { $otherNet.ContainsKey($_.IP) })
    Write-Host ""
    Write-Host "  Hosts descubiertos   : $($hosts.Count)  (mi red: $($myNet.Count) | otras subredes: $($otherNet.Count))" -ForegroundColor White
    Write-Host "  Con puertos abiertos : $($conAlgo.Count)" -ForegroundColor White
    Write-Host "  Otras subredes activas: $($otrasAct.Count)" -ForegroundColor $(if($otrasAct.Count -gt 0){"Red"}else{"Green"})

    if ($otrasAct.Count -gt 0) {
        Write-Host ""
        Write-Host "  [!!] POSIBLE FALLA DE AISLAMIENTO:" -ForegroundColor Red
        foreach ($r in $otrasAct) {
            Write-Host "    $($r.IP) | $(GetSubnet $r.IP @($adapters)) | ICMP:$(if($r.ICMP){'SI'}else{'NO'}) | $($r.Open -join ', ')" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [OK] Sin acceso confirmado a otras subredes" -ForegroundColor Green
    }

    return @{
        Timestamp=$( Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Machine=$env:COMPUTERNAME; User="$env:USERDOMAIN\$env:USERNAME"
        Adapters=@($adapters); Hosts=$hosts
        MyNet=$myNet; OtherNet=$otherNet
        Results=@($results); OtherActive=$otrasAct
    }
}

#endregion

#region -- HTML --------------------------------------------------------------

function Export-HTML {
    param($R, [string]$Out)
    # Ruta de salida robusta - funciona desde cualquier ubicacion
    if (-not $Out -or $Out -eq ".") {
        $Out = Split-Path -Parent $MyInvocation.ScriptName
        if (-not $Out) { $Out = $PSScriptRoot }
        if (-not $Out) { $Out = [System.IO.Path]::GetTempPath() }
    }
    if (-not (Test-Path $Out)) {
        try { New-Item -ItemType Directory -Path $Out -Force | Out-Null } catch {}
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $file = [System.IO.Path]::Combine($Out, "reporte_$timestamp.html")

    $adRows = ($R.Adapters | ForEach-Object {
        "<tr><td>$($_.Name)</td><td><code>$($_.IP)/$($_.Prefix)</code></td><td><code>$($_.Subnet)</code></td><td>$(if($_.Gateway){"<code>$($_.Gateway)</code>"}else{"—"})</td></tr>"
    }) -join ""

    $hostRows = ($R.Hosts.Keys | Sort-Object | ForEach-Object {
        $h = $R.Hosts[$_]; $inO = $R.OtherNet.ContainsKey($_)
        $b = if ($inO) {"<span style='background:#3d2800;color:#ffa947;padding:1px 5px;border-radius:3px;font-size:11px'>Otra subred</span>"}
             else       {"<span style='background:#162032;color:#79c0ff;padding:1px 5px;border-radius:3px;font-size:11px'>Mi red</span>"}
        "<tr><td><code>$_</code></td><td>$b</td><td><code>$($h.Subnet)</code></td><td style='font-family:monospace;font-size:11px'>$(if($h.MAC){$h.MAC}else{"—"})</td><td style='font-size:11px;color:#8b949e'>$($h.Sources -join ", ")</td></tr>"
    }) -join ""

    $portRows = ($R.Results | Where-Object { $_.ICMP -or $_.Open.Count -gt 0 } | Sort-Object IP | ForEach-Object {
        $r=$_; $inO=if($R.OtherNet){$R.OtherNet.ContainsKey($r.IP)}else{$false}
        $rs=if($inO){" style='background:#1a1200'"}else{""}
        $ob=if($inO){"<span style='background:#4d1a1a;color:#ff7b7b;padding:1px 5px;border-radius:3px;font-size:11px;margin-left:4px'>OTRA RED</span>"}else{""}
        $ic=if($r.ICMP){"<td style='color:#56d364;text-align:center;font-weight:600'>SI</td>"}else{"<td style='color:#444;text-align:center'>—</td>"}
        $cells = @(21,22,23,80,443,445) | ForEach-Object {
            $pn = @{21="FTP";22="SSH";23="Telnet";80="HTTP";443="HTTPS";445="SMB"}[$_]
            if ("$pn($_)" -in $r.Open) {"<td style='color:#ffa947;text-align:center;font-weight:600'>OPEN</td>"}
            else {"<td style='color:#333;text-align:center'>—</td>"}
        }
        "<tr$rs><td><code>$($r.IP)</code>$ob</td>$ic$($cells -join '')</tr>"
    }) -join ""

    $lc=$R.MyNet.Count; $oc=$R.OtherNet.Count; $ac=$R.OtherActive.Count
    $tCol=if($ac -gt 0){"#ff7b7b"}else{"#56d364"}

    $alertHtml = if ($ac -gt 0) {
        $items=($R.OtherActive|ForEach-Object{"<li><code>$($_.IP)</code> — ICMP:$(if($_.ICMP){'SI'}else{'NO'}) — $($_.Open -join ', ')</li>"})-join ""
        "<div class='alert'><strong>[!!] POSIBLE FALLA DE AISLAMIENTO</strong><ul style='margin-top:8px;line-height:2'>$items</ul></div>"
    } else { "<div class='ok'>[OK] Sin acceso confirmado a otras subredes.</div>" }

    $html = @"
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Reporte Red</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9cdd4;padding:32px}
h1{color:#58a6ff;font-size:22px;border-bottom:1px solid #21262d;padding-bottom:14px;margin-bottom:20px}
h2{color:#79c0ff;font-size:15px;margin:28px 0 10px;padding-left:8px;border-left:3px solid #1f6feb}
.meta{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 20px;margin-bottom:24px;font-size:13px;color:#8b949e;line-height:2}
.meta strong{color:#e6edf3}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center}
.card .n{font-size:36px;font-weight:700}.card .l{font-size:12px;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;font-size:13px;margin-bottom:14px}
th{background:#1c2128;padding:9px 14px;text-align:left;color:#79c0ff;font-weight:500}
td{padding:8px 14px;border-top:1px solid #21262d;vertical-align:middle}
tr:hover td{background:#1c2128}
code{background:#21262d;padding:2px 6px;border-radius:4px;font-size:12px;color:#79c0ff}
.alert{background:#2d1010;border:1px solid #da3633;border-radius:8px;padding:14px;color:#ff7b7b;font-size:13px;margin-bottom:14px}
.ok{background:#1a3a1a;border:1px solid #2ea043;border-radius:8px;padding:12px 16px;color:#56d364;font-size:13px;margin-bottom:14px}
ul{padding-left:20px;line-height:2}
.muted{color:#8b949e;font-size:12px;margin-top:36px;border-top:1px solid #21262d;padding-top:14px}
</style></head><body>
<h1>Reporte de Descubrimiento de Red</h1>
<div class="meta"><strong>Fecha:</strong> $($R.Timestamp) &nbsp;|&nbsp; <strong>Equipo:</strong> $($R.Machine) &nbsp;|&nbsp; <strong>Usuario:</strong> $($R.User)</div>
<div class="grid">
  <div class="card"><div class="n">$($R.Hosts.Count)</div><div class="l">Hosts descubiertos</div></div>
  <div class="card"><div class="n">$lc</div><div class="l">En mi red</div></div>
  <div class="card"><div class="n" style="color:#ffa947">$oc</div><div class="l">En otras subredes</div></div>
  <div class="card"><div class="n" style="color:$tCol">$ac</div><div class="l">Con puertos abiertos</div></div>
</div>
<h2>Adaptadores</h2>
<table><tr><th>Nombre</th><th>IP</th><th>Subred</th><th>Gateway</th></tr>$adRows</table>
<h2>Hosts descubiertos</h2>
<table><tr><th>IP</th><th>Segmento</th><th>Subred</th><th>MAC</th><th>Fuente</th></tr>$hostRows</table>
<h2>Verificacion de puertos</h2>
<table><tr><th>IP</th><th style='text-align:center'>ICMP</th><th style='text-align:center'>FTP<br><small>21</small></th><th style='text-align:center'>SSH<br><small>22</small></th><th style='text-align:center'>Telnet<br><small>23</small></th><th style='text-align:center'>HTTP<br><small>80</small></th><th style='text-align:center'>HTTPS<br><small>443</small></th><th style='text-align:center'>SMB<br><small>445</small></th></tr>$portRows</table>
<h2>Aislamiento de red</h2>$alertHtml
<p class="muted">Sin privilegios de admin · Pasivo + SendPingAsync + TCP Connect · PS5.1</p>
</body></html>
"@
    $html | Out-File -FilePath $file -Encoding UTF8
    return $file
}

#endregion

Write-Banner
Write-Host "  Timeout   : ${Timeout}ms" -ForegroundColor Gray
Write-Host "  Ping sweep: $PingSweep" -ForegroundColor Gray

$R    = Invoke-Main -Ms $Timeout -DoPing $PingSweep
$html = Export-HTML -R $R -Out $OutputPath
Write-Host ""
Write-Host "  [OK] Reporte: $html" -ForegroundColor Cyan
Write-Host ""