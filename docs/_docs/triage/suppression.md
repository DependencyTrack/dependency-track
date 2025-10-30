---
title: Suppression
category: Triage Results
chapter: 5
order: 3
---

Individual findings can be suppressed regardless of analysis state. Suppressed findings will have a positive impact on
metrics whereas findings that are not suppressed will not.

Suppressed findings may:
* Decrease the number of 'Portfolio Vulnerability' metrics
* Decrease the number of 'Vulnerable Project' metrics
* Decrease the number of 'Vulnerable Component' metrics
* Decrease the number of vulnerabilities in specific components
* Decrease the 'Inherited Risk Score'

Findings that are not suppressed will continue to have an impact on all metrics. Once a finding has been suppressed,
it will remain in that state unless a user specifically removes the suppression from the finding.

### Best Practice

Findings with an analysis state of NOT_AFFECTED or FALSE_POSITIVE should be suppressed so that the inherited risk
and corresponding metrics take into consideration the analysis decision.

A comment of why the issue is a false positive, or why the vulnerability does not affect the project should be made
prior to the issue being suppressed. This will provide auditors details of why specific decisions were made.

### Impact on External Systems

By suppressing findings, external systems will, by default, have the same positive impact on metrics. Suppressing a 
finding will have a positive impact not only on Dependency-Track itself, but the metrics of external systems as well.

For example, vulnerability aggregation platforms such as Kenna Security or ThreadFix will become aware of the updated
list of findings and metrics the next time they sync. These systems will assume suppressed findings have been 'fixed'.