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
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -Body $body
	    $fund = $response | ConvertFrom-Json

        if ($response.StatusCode -eq 200) 
            { 
            if ($response.Content -ne "[]") 
				{
				'Project affected: ' + $vulnerability.cveID + ' : ' + $fund.name + " v." + $fund.version + " UUID: " + $fund.uuid
				}
            else
                {
                # not affected
                # print it just for debug purpose!
                # $vulnerability.cveID + ': not affected'
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

