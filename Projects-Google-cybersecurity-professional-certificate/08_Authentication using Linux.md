# <p align="center"> Authentication using Linux </p>

## Project Overview

I simulated the role of a cybersecurity analyst responsible for managing user access on a Linux system. Specifically, I was tasked with authorizing a new user, managing their group memberships, handling file ownership, and eventually removing the user when they left the organization.

In this task, I worked with a new employee, researcher9, and managed their access and permissions throughout their tenure in the organization.

## Objectives

* Add a new user using `sudo` and `useradd`
* Assign a user to a primary group using `sudo` and `usermod`
* Change user permissions on files using `sudo` and  `chown`
* Add a user to secondary groups using `sudo` and `usermod`
* Delete a user and remove their associated group using `sudo`, `userdel` and `groupdel`

## Process

### Task 1: Add a new user
A new employee, **researcher9**, joined the Research department. To create their user account and assign them to the **research_team** group as their primary group, I ran the following command:

`sudo useradd researcher9 -g research_team`

### Task 2: Assign file ownership
**researcher9** was tasked with taking over **project_r**, a project initially managed by **researcher2**. The project file, `project_r.txt`, was located in `/home/researcher2/projects/`. I reassigned ownership of the file to **researcher9** using the following command:

`sudo chown researcher9 /home/researcher2/projects/project_r.txt`

### Task 3: Add the user to a secondary group
A few months later, **researcher9’s** role expanded to include responsibilities in the Sales department. To reflect this change, I added researcher9 to the **sales_team** group, while keeping their primary group as **research_team**:

`sudo usermod -a -G sales_team researcher9`

### Task 4: Delete a user
After a year, **researcher9** left the company. I removed their user account from the system with the following command:

`sudo userdel researcher9`
This resulted in the following output:
`userdel: group researcher9 not removed because it is not the primary group of user researcher9.`

This output occurs because when a user is created in Linux, a group with the same name is automatically generated. Since **researcher9’s** primary group was **research_team**, the system didn’t automatically remove the **researcher9** group. I cleaned up the leftover group using:

`sudo groupdel researcher9`

## Result

* Ensured that only authorized users had access to the system.

* Effectively added new users to the system and assigned them appropriate groups.

* Managed user access when an employee transitioned to a different department or role.

* Properly removed users and cleaned up associated resources when they left the organization.

## Reflection
This project reinforced the importance of **Identity and Access Management (IAM)** in securing sensitive organizational data. Proper user authentication, group management, and permission assignments ensure that only authorized individuals have access to critical resources.

By learning how to manage user roles, permissions, and cleanly remove access upon an employee’s departure, I gained valuable experience in maintaining a secure and organized Linux system.