---
title: Analysis States
category: Triage Results
chapter: 5
order: 2
---

When triaging results, an analysis decision can be made for each finding. The following states are supported:


| State | Description |
| ------|-------------|
|EXPLOITABLE| The finding is exploitable (or likely exploitable) |
|IN_TRIAGE| An investigation is in progress to determine if the finding is accurate and affects the project or component |
|FALSE_POSITIVE| The finding was identified through faulty logic or data (i.e. misidentified component or incorrect vulnerability intelligence) |
|NOT_AFFECTED| The finding is a true positive, but the project is not affected by the vulnerability identified |
|NOT_SET| Analysis of the finding has not commenced |

Audit history is maintained for every finding including changes to analysis states. The user making the change
along with a timestamp the change occurred is appended to the audit trail. 