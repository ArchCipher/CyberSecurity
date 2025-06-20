# <p align="center"> NIST CSF-Based Data Handling </p>

## Project Overview

I simulated the role of a security analyst for an edtech company that built an application to help teachers grade assignments. I investigated a data leak involving internal business documents. The leak occurred when an employee accidentally shared sensitive files with a business partner, who later posted them on social media.

The incident highlighted a failure to enforce the principle of least privilege during a sales meeting. I analyzed the root cause, reviewed the relevant controls, and recommended improvements to prevent similar breaches in the future.

---

## Data leak worksheet

**Incident summary:** A sales manager shared access to a folder of internal-only documents with their team during a meeting. The folder contained files associated with a new product that has not been publicly announced. It also included customer analytics and promotional materials. After the meeting, the manager did not revoke access to the internal folder, but warned the team to wait for approval before sharing the promotional materials with others.

During a video call with a business partner, a member of the sales team forgot the warning from their
manager. The sales representative intended to share a link to the promotional materials so that the
business partner could circulate the materials to their customers. However, the sales representative
accidentally shared a link to the internal folder instead. Later, the business partner posted the link on
their company's social media page assuming that it was the promotional materials.

| Control | Least privilege (AC-06) |
|---------|-----------------|
| Issue(s) | Access to the internal folder was not restricted to the sales team. The manager failed to revoke access after the meeting, and a business partner unintentionally received internal documents. |
| Review | NIST SP 800-53: AC-6 emphasizes restricting user access to only what's necessary for their role. It also includes enhancements for reviewing privileges and limiting access for non-organizational users. |
| Recommendation(s) | - Restrict access to sensitive folders based on user roles. <br> - Prohibit privileged access to internal systems by non-organizational users. <br> - Review and revoke access rights after project-specific use. |
| Justification | Implementing these controls limits exposure of confidential data. Role-based access and regular privilege audits help prevent unauthorized users from accessing internal resources or accidentally leaking them. Automating security tasks whenever possible would reduce the chances of human error. A policy such as setting expiration dates would have avoided this data leak. |

---

## Security plan snapshot
The NIST Cybersecurity Framework (CSF) uses a hierarchical, tree-like structure to organize information. From left to right, it describes a broad security function, then becomes more specific as it branches out to a category, subcategory, and individual security controls.

| Function | Category | Subcategory | Reference(s) |
|----------|----------|--------------|----------|
| Protect | PR.DS: Data security | PR.DS-5: Protections against data leaks. | [NIST SP 800-53: AC-6](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf#page=63) |

The recommended controls align with [NIST SP 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) particularly [AC-6](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf#page=63), which outlines the principle of least privilege and associated control enhancements to prevent data leaks.

---

## Reflection

Applying NIST controls specifically AC-6 on least privilege can significantly reduce the risk of data leaks caused by mismanaged access. Through this project, I learned how to interpret relevant NIST guidelines and recommend control enhancements aligned with organizational roles and responsibilities. It also reinforced the importance of regularly reviewing and revoking access to sensitive data, especially when external stakeholders are involved.

---