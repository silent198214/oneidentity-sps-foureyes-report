# Foureyes Audit Report of Safeguard for Privileged Sessions

Oneidentity Safeguard for Privileged Sessions (SPS) 7 版之後已經無法用 sql query 去客製化報表

利用 PowerShell core 7 組合查詢 SPS 提供的 REST API, 找出 sessions 並查詢 channel 裡的 foureyes 資訊，統整後產製 csv 檔

CSV 預設欄位有 `StartTime, UserName, FourEyesAuthorizer, FourEyesDescription`


## Requirements
* Powershell 7

## Parameters

|variable name|description|
|:-:|:-:|
|sps_server|SPS Hostname or IP|
|sps_login_method|ldap or local, by user store|
|sps_user|user account|
|sps_pass|user password|
|sps_filter|search query, Ex. `client.name: x.x.x.x AND user.name:*`|
|sps_startdate|start date by report time range|
|sps_enddate|end date by report time range|

## How to Use

Execute this ps1 file direct

```powershell
PS> foureyes-audit-report.ps1 
```

## Author Information

Sam Chen
