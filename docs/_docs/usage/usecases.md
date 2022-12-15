---
title: Use Cases
category: Usage
chapter: 2
order: 6
---

Here we provide some practical examples on how to use Dependency Track and its API. These are working examples but please add rights management, error management, monitoring etc. to fit your environment.

#### Preparations
You need an API-Key to use the REST API of Dependency Track. 

![API-key](/images/screenshots/API-key.png)

To get one, go to the Administration side menue, select Access Management and Teams. If there is no API key present, 
generate one by clicking at the blue plus icon. With this key in your hand, tha API opens to you. By the way: Using 
administrative rights is a sign of bad software engeneering. At the other hand it rolls some stones out of your way 
doing your first steps.

#### Import a SBoM
The following script imports all SBoM files in the working directory. It expects JSON format. It creates Dependency 
Track projects if they dont exist. 

```
$x_api_key = 'GaVkRIERpXU0lVOgo1onSRrIhTNV1eMm'     # Admin


function Send-Put
{
    param(
        [String] $url,
        $Body
    )

    $Headers= @{
            'accept' = 'application/json'
            'content-type' = 'application/json'
            'X-Api-Key' = $x_api_key
            }

    $response = Invoke-WebRequest -Uri $url -Method Put -Headers $Headers -Body $Body
    return ( $response | ConvertFrom-Json)
}

function Send-Get
{
    param(
        [String] $url
        )

    $Headers= @{
            'accept' = 'application/json'
            'X-Api-Key' = $x_api_key
            }

    $response = Invoke-WebRequest -Uri $url -Method Get -Headers $Headers
    return ( $response | ConvertFrom-Json)
}

# expecting a Docker Desktop environment, installed as provided
$urlDT = 'http://localhost:8081'

#get all .json files in directory
$BomFiles = Get-ChildItem -Path *.json -Name

foreach ($bx_file in $BomFiles)
    {
    $ProjectName = [System.IO.Path]::GetFileNameWithoutExtension($bx_file)
    $File_SBoM = ( Get-Content -path $bx_file | ConvertFrom-Json) 

    '[INFO] searching for project: ' + $ProjectName
    try {
        $data_file = ( Get-Content -path ($ProjectName + '.data') | ConvertFrom-Json)

        $funde1 = (Send-Get -url ($urlDT + "/api/v1/search/project?query=" + $ProjectName)).results.project
        # How many projects were found?
        if  ( $funde1.Length -eq 0) 
            {
			'[INFO] no existing project found, importing project: ' + $ProjectName 
            $bom64 = [convert]::ToBase64String((Get-Content -path $bx_file -Encoding byte))
            Send-Put -url ($urlDT + "/api/v1/bom") -Body ("{""projectName"":""" + $ProjectName + """,""projectVersion"":""" + $data_file.versionDT + """,""autoCreate"":""true"", ""bom"":""" + $bom64 + """}")
			}
                           
        }
    catch 
        {
        '[ERROR] ' + $_.Exception.Message
        '[ERROR] ' + $_.ScriptStackTrace
        }         
    }
```


#### Integrate CISAs List of known exploited vulnerabilities
The [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) maintains a catalog of known exploited vulnerabilities. They 
offer a notification service, too. Use the following script to learn if a vulnerability in your aplications is already exploited. For even
more comfort subscribe to CISA and let the cript trigger by their e-mail.

```
# expecting a Docker Desktop environment, installed as provided
$urlDT = 'http://localhost:8081'
$x_api_key = 'GaVkRIERpXU0lVOgo1onSRrIhTNV1eMm'

# get CISAs catalog
$urlCISA = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$catalog = (Invoke-WebRequest -Uri $urlCISA -Method Get).content | ConvertFrom-Json

# compare CISA to DT
# curl -X GET "http://localhost:8081/api/v1/vulnerability/source/NVD/vuln/CVE-2022-23305/projects" -H  "accept: application/json" -H  "X-Api-Key: GaVkRIERpXU0lVOgo1onSRrIhTNV1eMn"

$headers= @{
            'accept' = 'application/json'
            'X-Api-Key' = $x_api_key
            }

foreach ($vulnerability in $catalog.vulnerabilities)
    {
    #call DT 
    $uri = $urlDT + "/api/v1/vulnerability/source/NVD/vuln/" + $vulnerability.cveID + "/projects"
    $response = ""

    try {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers
	    $funde = $response | ConvertFrom-Json

        if ($response.StatusCode -eq 200) 
            { 
            forEach ($fund in $funde)
                {
                $vulnerability.cveID + ' : ' + $fund.name + " v." + $fund.version + " UUID: " + $fund.uuid
                }
			}
        }
    catch 
        {
        'error: ' + $uri + ' / ' + $vulnerability.cveID + " : " + $response
        $_.Exception.Message
        $_.ScriptStackTrace
        }         
    }
```

#### Risk based vulnerability management
The [FIRST](https://www.first.org/epss/) publishes an Exploit Prediction Scoring System. The rough idea is easy: Not each vulnerability will be exploited. 
So you don't have to patch all vulnerabilities of your code. Please have a look at the FIRST site for all the details. Dependency Track supports EPSS. 
Here we will show how to use it. Our script selects Vulnerabilities with CVSS greater then 5 and EPSS greater then 0.5 The script writes the result in 
an Excel file: c:\temp\cvss-epss.xlsx.

```
$urlDT = 'http://localhost:8081'
$x_api_key = 'GaVkRIERpXU0lVOgo1onSRrIhTNV1eMm'
$Myfile = 'C:\temp\cvss-epss.xlsx'
$cvssMin = 5
$epssMin = 0.5
$headers= @{
           'accept' = 'application/json'
           'X-Api-Key' = $x_api_key
            }

try {
	#prepare Excel File 
	$Myexcel = New-Object -ComObject excel.application
	$Myexcel.visible = $false
	$Myworkbook = $Myexcel.workbooks.add()
	$Sheet1 = $Myworkbook.worksheets.item(1)
	$Sheet1.name = "EPSS-CVSS"

	$Sheet1.cells.item(1,1) = 'NAME'
	$Sheet1.cells.item(1,2) = 'VERSION'
	$Sheet1.cells.item(1,3) = 'UUID'
	$Sheet1.cells.item(1,4) = 'VULN-ID'
	$Sheet1.cells.item(1,5) = 'CVSS'
	$Sheet1.cells.item(1,6) = 'EPSS'
	$Sheet1.cells.item(1,7) = 'COMPONENT-NAME'
	$Sheet1.cells.item(1,8) = 'COMPONENT-VERSION'

	$line = 2

    $response = Invoke-WebRequest -Uri ($urlDT + '/api/v1/project') -Method Get -Headers $headers
    $projects = $response | ConvertFrom-Json
	# search entries
	foreach ($fund in $projects)
		{

		#call DT 
		# $fund.name + " v." + $fund.version + " UUID: " + $fund.uuid

		$response = Invoke-WebRequest -Uri ($urlDT + '/api/v1/vulnerability/project/' + $fund.uuid) -Method Get -Headers $headers
		$vulns = $response | ConvertFrom-Json
		foreach ($vuln in $vulns)
			{
			$cvss = [Float]$vuln.cvssV3BaseScore
			$epss = [Float]$vuln.epssScore
			if ( ($cvss -gt $cvssMin) -and ( $epss -gt $epssMin) ) 
				{
				foreach ($comp in $vuln.components)
					{
					$fund.name + ";" + $fund.version + ";" + $fund.uuid + ";" + $vuln.vulnID + ";" + $vuln.cvssV3BaseScore + ";" + $vuln.epssScore + ";" + $comp.name + ";" + $comp.version
										
					# set text format 
					$Sheet1.cells.item($line,1).NumberFormat = "@"
					$Sheet1.cells.item($line,1) = $fund.name
					$Sheet1.cells.item($line,2).NumberFormat = "@"
					$Sheet1.cells.item($line,2) = $fund.version
										
					$Sheet1.cells.item($line,3).NumberFormat = "@"
					$Sheet1.cells.item($line,3) = $fund.uuid
					$Sheet1.cells.item($line,4).NumberFormat = "@"
					$Sheet1.cells.item($line,4) = $vuln.vulnID
					$Sheet1.cells.item($line,5).NumberFormat = "@"
					$Sheet1.cells.item($line,5) = $vuln.cvssV3BaseScore
					$Sheet1.cells.item($line,6).NumberFormat = "@"
					$Sheet1.cells.item($line,6) = $vuln.epssScore
					$Sheet1.cells.item($line,7).NumberFormat = "@"
					$Sheet1.cells.item($line,7) = $comp.name
					$Sheet1.cells.item($line,8).NumberFormat = "@"
					$Sheet1.cells.item($line,8) = $comp.version
					$line++
					}
				} 
			}
		}
		$Myworkbook.Saveas($Myfile)
		$Myexcel.Quit()
    }
catch 
    {
    'error: ' + $response
    $_.Exception.Message
    $_.ScriptStackTrace
    }

```

