# <p align="center"> Authentication, Authorization, and Accounting  </p>

## Project Overview

I simulated the role of first cybersecurity professional hired by a growing business. I reviewed the access log of the incident, assessed the current access controls, analyzed their current process, identified issues, and made recommendations to improve their security practices.

## Scenario

Recently, a deposit was made from the business to an unknown bank account. The finance manager says they didn't make a mistake. Fortunately, they were able to stop the payment. The owner requested me to investigate what happened to prevent any future incidents.

---

## Supporting materials

|Event log|
|--------|
|Event Type: Information|
Event Source: AdsmEmployeeService
Event Category: None
Event ID: 1227
Date: 10/03/2023
Time: 8:29:57 AM
User: Legal\Administrator
Computer: Up2-NoGud
IP: 152.207.255.255
Description: Payroll event added. FAUX_BANK

### Employee Directory

| Name | Role | Email | IP address | Status | Authorization | Last access | Start date | End date |
|------|------|-------|------------|--------|---------------|-------------|------------|----------|
| Lisa Lawrence | Office manager | l.lawrence@erems.net | 118.119.20.150 | Full-time | Admin | 12:27:19 pm (0 minutes ago) | 10/1/2019 | N/A |
| Jesse Pena | Graphic designer | j.pena@erems.net | 186.125.232.66 | Part-time | Admin | 4:55:05 pm (1 day ago) | 11/16/2020 | N/A |
| Catherine Martin | Sales associate | catherine_M@erems.net | 247.168.184.57 | Full-time | Admin | 12:17:34 am (10 minutes ago) | 10/1/2019 | N/A |
| Jyoti Patil | Account manager | j.patil@erems.net | 159.250.146.63 | Full-time | Admin | 10:03:08 am (2 hours ago) | 10/1/2019 | N/A |
| Joanne Phelps | Sales associate | j_phelps123@erems.net | 249.57.94.27 | Seasonal | Admin | 1:24:57 pm (2 years ago) | 11/16/2020 | 1/31/2020 |
| Ariel Olson | Owner | a.olson@erems.net | 19.7.235.151 | Full-time | Admin | 12:24:41 pm (4 minutes ago) | 8/1/2019 | N/A |
| Robert Taylor Jr. | Legal attorney | rt.jr@erems.net | 152.207.255.255 | Contractor | Admin | 8:29:57 am (5 days ago) | 9/4/2019 | 12/27/2019 |
| Amanda Pearson | Manufacturer | amandap987@erems.net | 101.225.113.171 | Contractor | Admin | 6:24:19 pm (3 months ago) | 8/5/2019 | N/A |
| George Harris | Security analyst | georgeharris@erems.net | 70.188.129.105 | Full-time | Admin | 05:05:22 pm (1 day ago) | 1/24/2022 | N/A |
| Lei Chu | Marketing | lei.chu@erems.net | 53.49.27.117 | Part-time | Admin | 3:05:00 pm (2 days ago) | 11/16/2020 | 1/31/2020 |

---

## Access Control Worksheet

### Notes:

The event log indicates a payroll event (ID: 1227) was added to FAUX_BANK on 10/03/2023 at 8:29 AM from IP address 152.207.255.255 using Legal\Administrator credentials on device Up2-NoGud.

Cross-referencing the employee directory reveals this IP belongs to Robert Taylor Jr., a legal attorney contractor whose employment terminated on 12/27/2019, yet his account retained admin privileges.

Additional terminated employees with active admin access include Lei Chu (Marketing, accessed 2 days ago) and Joanne Phelps (Sales associate, accessed 2 years ago).

A suspicious login occurred at 12:17 AM from IP address 247.168.184.57, associated with Catherine Martin, a current sales associate. This activity requires monitoring but appears unrelated to the primary breach.

### Primary Issue:

**Expired Contractor Access**: Robert Taylor Jr.'s account remained active with full admin privileges four years post-termination, enabling the unauthorized financial transaction.

### Other Identified Vulnerabilities:

**Terminated Employee Access**: Former employees (Lei Chu, Joanne Phelps) retain admin privileges despite contract completion.

**Excessive Privilege Assignment**: All current employees possess administrative access regardless of role requirements, violating least privilege principles.

### Recommended Controls:

* Implement automated account deactivation triggered by employment termination dates.

* Establish permissions based on job functions, eliminating full administrative access.


* Conduct access reviews to identify and revoke inappropriate permissions.

---

## Summary

This incident investigation revealed a security breach caused by inadequate access control management. The unauthorized payroll transaction to FAUX_BANK was executed by Robert Taylor Jr., a contractor whose account remained active with full admin privileges four years after termination.

The analysis identified several access issues including terminated employees retaining access and excessive privileges for all staff. Implementing automated account deactivation and role-based access controls would prevent similar incidents.

---

## Notes