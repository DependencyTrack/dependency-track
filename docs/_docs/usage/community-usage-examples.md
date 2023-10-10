---
title: Community Usage Examples
category: Usage
chapter: 2
order: 7
---

This page lists various usage examples of Dependency-Track and its REST API that have been contributed by the community.

### Finding vulnerabilities from CISA KEV in Dependency-Track

> Contributed by [JoergBruenner](https://github.com/JoergBruenner)

CISA maintains a [catalog of known exploited vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (KEV). 
The following powershell script may be used to quickly identify projects in the Dependency-Track portfolio that are 
affected by vulnerabilities listed in KEV.

```powershell
$api_base_url = 'http://localhost:8081'
$api_key = 'changeit'

$urlCISA = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$catalog = (Invoke-WebRequest -Uri $urlCISA -Method Get).content | ConvertFrom-Json

$headers = @{
    'accept' = 'application/json'
    'X-Api-Key' = $api_key
}

foreach ($vulnerability in $catalog.vulnerabilities)
{
    $uri = $api_base_url + "/api/v1/vulnerability/source/NVD/vuln/" + $vulnerability.cveID + "/projects"
    $response = ""

    try
    {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers
        $affected_projects = $response | ConvertFrom-Json

        if ($response.StatusCode -eq 200)
        {
            forEach ($project in $affected_projects)
            {
                $vulnerability.cveID + ': ' + $project.name + " v." + $project.version + " UUID: " + $project.uuid
            }
        }
    }
    catch
    {
        '[ERROR]: ' + $uri + ' / ' + $vulnerability.cveID + " : " + $response
        '[ERROR] ' + $_.Exception.Message
        '[ERROR] ' + $_.ScriptStackTrace
    }
}
```

### Creating Excel reports from EPSS data

> Contributed by [JoergBruenner](https://github.com/JoergBruenner)

The FIRST [exploit prediction scoring system](https://www.first.org/epss/) (EPSS) can help with prioritizing remediation
efforts, by giving estimations of the likelihood that vulnerabilities are being exploited in the wild.
Dependency-Track has native support for EPSS, and surfaces this data directly in the UI, or in its REST API.

> Note that EPSS is only supported for published CVEs. Vulnerabilities sourced from [GitHub Advisories], [OSV], 
> or [Snyk] will not have EPSS scores assigned to them.

The following Powershell script may be used to create an Excel report of all vulnerable components in the Dependency-Track
portfolio, where both the CVSSv3 and EPSS scores exceed a given threshold. For each vulnerable component, the report
will include identifiers of the component, the vulnerability it is affected by, the project the component belongs to,
as well as the respective CVSSv3 and EPSS scores. 

```powershell
$api_base_url = 'http://localhost:8081'
$api_key = 'changeit'
$output_file = 'C:\temp\cvss-epss.xlsx'
$cvssMin = 5
$epssMin = 0.5
$headers = @{
    'accept' = 'application/json'
    'X-Api-Key' = $api_key
}

try
{
    $my_excel = New-Object -ComObject excel.application
    $my_excel.visible = $false
    $my_workbook = $my_excel.workbooks.add()
    $sheet_1 = $my_workbook.worksheets.item(1)
    $sheet_1.name = "EPSS-CVSS"

    $sheet_1.cells.item(1, 1) = 'NAME'
    $sheet_1.cells.item(1, 2) = 'VERSION'
    $sheet_1.cells.item(1, 3) = 'UUID'
    $sheet_1.cells.item(1, 4) = 'VULN-ID'
    $sheet_1.cells.item(1, 5) = 'CVSS'
    $sheet_1.cells.item(1, 6) = 'EPSS'
    $sheet_1.cells.item(1, 7) = 'COMPONENT-NAME'
    $sheet_1.cells.item(1, 8) = 'COMPONENT-VERSION'

    $line = 2

    $response = Invoke-WebRequest -Uri ($api_base_url + '/api/v1/project') -Method Get -Headers $headers
    $projects = $response | ConvertFrom-Json

    foreach ($project in $projects)
    {
        $response = Invoke-WebRequest -Uri ($api_base_url + '/api/v1/vulnerability/project/' + $project.uuid) -Method Get -Headers $headers
        $vulns = $response | ConvertFrom-Json
        foreach ($vuln in $vulns)
        {
            $cvss = [Float]$vuln.cvssV3BaseScore
            $epss = [Float]$vuln.epssScore
            if (($cvss -gt $cvssMin) -and ( $epss -gt $epssMin))
            {
                foreach ($comp in $vuln.components)
                {
                    $project.name + ";" + $project.version + ";" + $project.uuid + ";" + $vuln.vulnID + ";" + $vuln.cvssV3BaseScore + ";" + $vuln.epssScore + ";" + $comp.name + ";" + $comp.version

                    # Set text format
                    $sheet_1.cells.item($line, 1).NumberFormat = "@"
                    $sheet_1.cells.item($line, 1) = $project.name
                    $sheet_1.cells.item($line, 2).NumberFormat = "@"
                    $sheet_1.cells.item($line, 2) = $project.version

                    $sheet_1.cells.item($line, 3).NumberFormat = "@"
                    $sheet_1.cells.item($line, 3) = $project.uuid
                    $sheet_1.cells.item($line, 4).NumberFormat = "@"
                    $sheet_1.cells.item($line, 4) = $vuln.vulnID
                    $sheet_1.cells.item($line, 5).NumberFormat = "@"
                    $sheet_1.cells.item($line, 5) = $vuln.cvssV3BaseScore
                    $sheet_1.cells.item($line, 6).NumberFormat = "@"
                    $sheet_1.cells.item($line, 6) = $vuln.epssScore
                    $sheet_1.cells.item($line, 7).NumberFormat = "@"
                    $sheet_1.cells.item($line, 7) = $comp.name
                    $sheet_1.cells.item($line, 8).NumberFormat = "@"
                    $sheet_1.cells.item($line, 8) = $comp.version
                    $line++
                }
            }
        }
    }
    $my_workbook.Saveas($output_file)
    $my_excel.Quit()
}
catch
{
    'error: ' + $response
    $_.Exception.Message
    $_.ScriptStackTrace
}
```

[GitHub Advisories]: {{ site.baseurl }}{% link _docs/datasources/github-advisories.md %}
[OSV]: {{ site.baseurl }}{% link _docs/datasources/osv.md %}
[Snyk]: {{ site.baseurl }}{% link _docs/datasources/snyk.md %}