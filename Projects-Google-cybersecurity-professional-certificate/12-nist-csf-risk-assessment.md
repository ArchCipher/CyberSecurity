# <p align="center"> NIST CSF-Based Risk Assessment </p>

## Project Overview

I simulated the role of a cybersecurity analyst at a commercial bank. As part of a formal risk assessment, I evaluated a set of risk recorded in the organization’s risk register. For each risk, I assessed the likelihood of occurrence, the potential impact, and calculated an overall risk score to prioritize mitigation efforts. This process supports the bank in aligning with the NIST Cybersecurity Framework (CSF).

---

## Risk Register

### Operational environment:
The bank is located in a coastal area with low crime rates. Many people and systems handle the bank's data—100 on-premise employees and 20 remote employees. The customer base of the bank includes 2,000 individual accounts and 200 commercial accounts. The bank's services are marketed by a professional sports team and ten local businesses in the community. There are strict financial regulations that require the bank to secure their data and funds, like having enough cash available
each day to meet **Federal Reserve** requirements.

---

### Risk Table
| Asset | Risk(s) | Description | Likelihood | Severity | Priority |
|-------|---------|-------------|------------|----------|----------|
| Funds | Business email compromise | An employee is tricked into sharing confidential information. | 2 | 2 | 4 |
| Funds | Compromised user database | Customer data is poorly encrypted. | 2 | 3 | 6 |
| Funds | Financial records leak | A database server of backed up data is publicly accessible. | 3 | 3 | 9 |
| Funds | Theft | The bank's safe is left unlocked. | 1 | 3 | 3 |
| Funds | Supply chain disruption | Delivery delays due to natural disasters. | 1 | 2 | 2 |

**Note:** Additional risk factors that could have been considered include the number of external stakeholders that interact with the bank. These third parties may introduce risks that are beyond the bank’s direct control. Also, while the current risk of theft is deemed low, it should not be dismissed due to the potential impact on daily operations and customer trust, especially given the number of accounts managed.

---

### Risk Matrix Used

| Severity → <br> Likelihood ↓| Low <br> 1 | Moderate <br> 2 | Catastrophic <br> 3 |
|:-------------:|:---------:|:-------------:|:-------------:|
| Rare <br> 1 | 1 | 2 | 3|
| Likely <br> 2 | 2 | 4 | 6|
| Certain <br> 3 | 3 | 6 | 9|

**Likelihood**: Probability that a vulnerability will be exploited (1 = low, 3 = high).

**Severity**: Potential impact if the risk is realized (1 = minimal, 3 = catastrophic).

**Priority** = Likelihood × Severity

---

## Recommendation & Insights

**High Priority**: Secure the publicly accessible backup server by restricting access and encrypting financial records.

**Medium Priority**: Encrypt and securely store customer databases. Train staff on phishing and enforce strong password policies.

**Lower Priority**: Theft is less urgent due to low local crime. Supply chain issues are unlikely but should be included in continuity plans

The **highest-priority risk** is the financial records leak due to a publicly accessible backup server which received the highest risk score of 9. This must be remediated immediately by implementing access controls and encrypting backups. This risk would impact the bank's reputation, and would face issues with compliance and financial consequences.

**Moderate-priority risk:**
* Compromised customer database: Implement strong encryption standards and secure storage protocols.
* Business email compromise: Conduct regular phishing-awareness training and enforce strict password policies.

**Lower Priority risk:** Although potentially impactful, theft is considered lower priority due to the bank's location in a low-crime area. Supply chain issues, while unlikely, should still be addressed in the bank’s business continuity plan.

---

## Summary

This risk assessment enabled the bank to identify and prioritize threats to its financial systems and data. Using a structured scoring model based on likelihood and impact helped guide risk mitigation steps aligned with the NIST CSF. Addressing the highest risks first ensures that limited resources are focused on protecting critical assets and maintaining regulatory compliance.

---