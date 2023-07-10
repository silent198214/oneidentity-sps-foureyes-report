param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Enter SPS IP or hostname")]
    [ValidateNotNullorEmpty ()]
    [string]$sps_server,

    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Enter Login Method (local or ldap...)")]
    [ValidateNotNullorEmpty ()]
    [string]$sps_login_method,

    [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Enter Login Account")]
    [ValidateNotNullorEmpty ()]
    [string]$sps_user,

    [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Enter Login Password")]
    [ValidateNotNullorEmpty ()]
    [Security.SecureString]$sps_pass,

    [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Enter Search Query")]
    [string]$sps_filter,

    [Parameter(Mandatory = $true, Position = 5, HelpMessage = "Enter Start Date")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$sps_startdate,

    [Parameter(Mandatory = $true, Position = 6 HelpMessage = "Enter End Date")]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$sps_enddate
)

### Variables Define ###
$outputfolder = "outputs"
### End Variables Define ###

#### Function ####
Function MainFunction {
    [CmdletBinding(ConfirmImpact = 'High')]
    Param ()
    Begin {

        # create folder to save reports files
        Write-Host "Create $outputfolder folder..."
        if (Test-Path -Path $outputfolder) {
            Write-Warning "$outputfolder folder is exists."
        }
        else {
            New-Item -Path $outputfolder -ItemType Directory 
            Write-Host "Folder created successfully. $outputfolder"
        }
    }
    Process {
        $LoginSaveSession = Login-SPS -Server $sps_server -Loginmethod $sps_login_method -Username $sps_user -Password $sps_pass

        if($null -eq $LoginSaveSession) {
            Write-Warning "Login SaveSession is Null, return False"
            return $false
        }

        $AuditSessions = Get-Audit-Sessions -Server $sps_server -Query $sps_filter -StartDate $sps_startdate -EndDate $sps_enddate -Session $LoginSaveSession

        if($null -eq $AuditSessions) {
            Write-Warning "Get Audit Sessions is Null, return False"
            return $false
        }
    }
}

Function Login-SPS {
    [CmdletBinding(ConfirmImpact='High' )]
    Param ( 
        [string] $Server,
        [string] $Username,
        [string] $Loginmethod,
        $Password
    )

    $params = @{
        Uri = "https://$($Server)/api/authentication?login_method=$($Loginmethod)&type=password"
        Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        Authentication = 'Basic'
    }

    Write-Host "Try to Login - $($Server)"
    try {
        $resp = Invoke-RestMethod @params -SessionVariable saveSession

        return $saveSession
    } catch [System.Exception] { 
        Write-Warning "Unable to Login SPS" 
        $FullEx = $_ | Select-Object -Property * | Out-String
        Write-Error $FullEx
        return $null
    }
}

Function Get-Audit-Sessions {
    [CmdletBinding(ConfirmImpact='High' )]
    Param ( 
        [string] $Server,
        [string] $Query,
        [string] $StartDate,
        [string] $EndDate,
        $Session
    )

    $AuditSessionUri = "https://$($Server)/api/audit/sessions"
    $ReportFile = $outputfolder + "\sps_foureyes_report_" + $StartDate + "_" + $EndDate + ".csv"
    $params_body = @{
        format = 'json'
        q = $Query
        sort = '-start_time'
        fields = 'start_time,end_time,protocol,server.ip,user.name'
        start = $StartDate
        end = $EndDate
    }

    Write-Host "Try to Call - $($AuditSessionUri)"
    try {
        $resp = Invoke-RestMethod -Uri $AuditSessionUri -Body $params_body -WebSession $Session
        if($resp.meta.match_count -eq 0) {
            return $null
        } else {
            Write-Host "Try to Call Channel Info API by Audit Sessions"
            $table = Foreach($resp_item in $resp.items){
                $result = Get-Channel-Audit -Server $Server -ChannelUri $resp_item.meta.href -Session $Session
                new-object psobject -Property @{
                    StartTime = $resp_item.body.start_time
                    UserName = $resp_item.body.user.name
                    FourEyesAuthorizer  = $result[0]
                    FourEyesDescription  = $result[1]
                }
            }
        
            Write-Host "Generating report file"
            $table | Select-Object StartTime,UserName,FourEyesAuthorizer,FourEyesDescription | Export-Csv -path $ReportFile -Encoding 950
            
            return $true
        }
    } catch [System.Exception] {
        Write-Warning "Unable to Get Audit sessions"
        $FullEx = $_ | Select-Object -Property * | Out-String 
        Write-Error $FullEx
        return $null
    }
}

Function Get-Channel-Audit {
    [CmdletBinding(ConfirmImpact='High' )]
    Param ( 
        [string] $Server,
        [string] $ChannelUri,
        $Session
    )

    $channel_uri = "https://$($Server+$ChannelUri)/channels"

    try {
        $resp = Invoke-RestMethod -Uri $channel_uri -WebSession $Session
        Foreach($resp_item in $resp.items){
            return $resp_item.four_eyes_authorizer, $resp_item.four_eyes_description
        }
        return $true
    } catch [System.Exception] {
        Write-Warning "Unable to Get Channel Audit Info"
        $FullEx = $_ | Select-Object -Property * | Out-String 
        Write-Error $FullEx
        return $null
    }
}

## Start Script ##
return MainFunction
## End   Script ## 
