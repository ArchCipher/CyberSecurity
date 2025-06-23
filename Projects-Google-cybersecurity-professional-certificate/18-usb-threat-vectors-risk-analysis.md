# <p align="center"> Healthcare USB Drive Threat Vectors & Risk Analysis </p>

## Project Overview

I simulated the role of a cybersecurity professional at Rhetorical Hospital and identified 8 attack vectors of a found USB drive and suggested several controls to be implemented.

## Scenario
You are part of the security team at Rhetorical Hospital and arrive to work one morning. On the ground of the parking lot, you find a USB stick with the hospital's logo printed on it. There's no one else around who might have dropped it, so you decide to pick it up out of curiosity.

You bring the USB drive back to your office where the team has virtualization software installed on a workstation. Virtualization software can be used for this very purpose because it's one of the only ways to safely investigate an unfamiliar USB stick. The software works by running a simulated instance of the computer on the same workstation. This simulation isn't connected to other files or networks, so the USB drive can't affect other systems if it happens to be infected with malicious software.

You create a virtual environment and plug the USB drive into the workstation. The contents of the device appear to belong to Jorge Bailey, the human resource manager at Rhetorical Hospital.

[Image of Jorge's USB files](./misc-images/18-1.png)

Jorge's drive contains a mix of personal and work-related files. For example, it contains folders that appear to store family and pet photos. There is also a new hire letter and an employee shift schedule.

---

## Parking lot USB exercise

### Contents Analysis
**Personal information**: Contains Jorge's personal files including family photos, vacation & wedding plans that he wouldn't want made public.

**Work Files**: Contains PII of other employees including new hire details and shift schedules. Contains sensitive information about hospital operations, employee budgets, and schedules.

**Storage Risk**: Storing personal files with work files violates data handling best practices and could violate HIPAA compliance requirements for healthcare organizations.

### Attacker Mindset
Both work and personal information could be used to trick Jorge, other employees, or his relatives through malicious emails designed to look like they come from trusted sources such as coworkers, family members, or wedding vendors.

Shift schedules provide intel about Jorge's coworkers and could be used for targeted attacks against other employees. It could help attackers gain unauthorized access to hospital areas when security is minimal.

### Risk Analysis

**Malware Threats:**
The USB could contain viruses, malware, rootkits, or advanced threats that would infect systems and potentially spread across the entire hospital network if plugged into an unprotected computer.

**Information Exposure:**
Attackers could access PII, hospital schedules, employee budgets, and personal information for social engineering attacks. This creates HIPAA violations and regulatory compliance risks.

**Attack Scenarios:**
Threat actors could impersonate colleagues or use personal information to manipulate Jorge and other employees, potentially gaining access to patient data and sensitive hospital systems.

### Security Controls to Implement:
- Data governance policies separating personal and work data
- Incident response procedures for found devices
- Disable AutoPlay on company computers to prevent automatic execution of malicious code
- Employee awareness training about USB-based attacks and suspicious devices
- USB port restrictions and device allowlisting
- Routine antivirus scanning for all devices

---

## Summary

This USB drive analysis revealed significant security risks from mixing personal and work data. The device contained sensitive hospital information and personal details that could enable social engineering attacks, malware infections, and unauthorized access. Key protections include disabling AutoPlay, employee training, and implementing proper data handling policies to maintain HIPAA compliance and protect patient data.

---

## Notes