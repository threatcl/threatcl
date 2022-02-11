//controls listed for MITRE ATT&CK

spec_version = "0.1.0"

component "control" "Account_Use_Policies" {
  description = "[M1036](https://attack.mitre.org/mitigations/M1036/) - Configure features related to account use like login attempt lockouts, specific login times, etc."
}
component "control" "Active_Directory_Configuration" {
  description = "[M1015](https://attack.mitre.org/mitigations/M1015/) - Configure Active Directory to prevent use of certain techniques; use SID Filtering, etc."
}
component "control" "Antivirus_Antimalware" {
  description = "[M1049](https://attack.mitre.org/mitigations/M1049/) - Use signatures or heuristics to detect malicious software."
}
component "control" "Application_Developer_Guidance" {
  description = "[M1013](https://attack.mitre.org/mitigations/M1013/) This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of."
}
component "control" "Application_Isolation_and_Sandboxing" {
  description = "[M1048](https://attack.mitre.org/mitigations/M1048/) Restrict execution of code to a virtual environment on or in transit to an endpoint system.\"
}
component "control" "Audit" {
  description = "[M1047](https://attack.mitre.org/mitigations/M1047/) Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses."
}
component "control" "Behavior_Prevention_on_Endpoint" {
  description = "[M1040](https://attack.mitre.org/mitigations/M1040/) Use capabilities to prevent suspicious behavior patterns from occurring on endpoint systems. This could include suspicious process, file, API call, etc. behavior."
}
component "control" "Boot_Integrity" {
  description = "[M1046](https://attack.mitre.org/mitigations/M1046/) Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms."
}
component "control" "Code_Signing" {
  description = "[M1045](https://attack.mitre.org/mitigations/M1045/) Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing."
}
component "control" "Credential_Access_Protection" {
  description = "[M1043](https://attack.mitre.org/mitigations/M1043/) Use capabilities to prevent successful credential access by adversaries; including blocking forms of credential dumping."
}
component "control" "Data_Backup" {
  description = "[M1053]([https://attack.mitre.org/mitigations/M1053/) Take and store data backups from end user systems and critical servers. Ensure backup and storage systems are hardened and kept separate from the corporate network to prevent compromise."
}
component "control" "Data_Loss_Prevention" {
  description = "[M1057](https://attack.mitre.org/mitigations/M1057/) Use a data loss prevention (DLP) strategy to categorize sensitive data, identify data formats indicative of personal identifiable information (PII), and restrict exfiltration of sensitive data."
}
component "control" "Disable_or_Remove_Feature_or_Program" {
  description = "[M1042](https://attack.mitre.org/mitigations/M1042/) Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries."
}
component "control" "Do_Not_Mitigate" {
  description = "[M1055](https://attack.mitre.org/mitigations/M1055/) This category is to associate techniques that mitigation might increase risk of compromise and therefore mitigation is not recommended."
}
component "control" "Encrypt_Sensitive_Information" {
  description = "[M1041](https://attack.mitre.org/mitigations/M1041/) Protect sensitive information with strong encryption."
}
component "control" "Environment_Variable_Permissions" {
  description = "[M1039](https://attack.mitre.org/mitigations/M1039/) Prevent modification of environment variables by unauthorized users and groups."
}
component "control" "Execution_Prevention" {
  description = "[M1038](https://attack.mitre.org/mitigations/M1038/) Block execution of code on a system through application control, and/or script blocking."
}
component "control" "Exploit_Protection" {
  description = "[M1050](https://attack.mitre.org/mitigations/M1050/) Use capabilities to detect and block conditions that may lead to or be indicative of a software exploit occurring."
}
component "control" "Filter_Network_Traffic" {
  description = "[M1037](https://attack.mitre.org/mitigations/M1037/) Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic."
}
component "control" "Limit_Access_to_Resource_Over_Network" {
  description = "[M1035](https://attack.mitre.org/mitigations/M1035/) Prevent access to file shares, remote access to systems, unnecessary services. Mechanisms to limit access may include use of network concentrators, RDP gateways, etc."
}
component "control" "Limit_Hardware_Installation" {
  description = "[M1034](https://attack.mitre.org/mitigations/M1034/) Block users or groups from installing or using unapproved hardware on systems, including USB devices."
}
component "control" "Limit_Software_Installation" {
  description = "[M1033](https://attack.mitre.org/mitigations/M1033/) Block users or groups from installing unapproved software."
}
component "control" "Multi-factor_Authentication" {
  description = "[M1032](https://attack.mitre.org/mitigations/M1032/) Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator."
}
component "control" "Network_Intrusion_Prevention" {
  description = "[M1031](https://attack.mitre.org/mitigations/M1031/) Use intrusion detection signatures to block traffic at network boundaries."
}
component "control" "Network_Segmentation" {
  description = "[M1030](https://attack.mitre.org/mitigations/M1030/) Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information. Use a DMZ to contain any internet-facing services that should not be exposed from the internal network. Configure separate virtual private cloud (VPC) instances to isolate critical cloud systems."
}
component "control" "Operating_System_Configuration" {
  description = "[M1028](https://attack.mitre.org/mitigations/M1028/) Make configuration changes related to the operating system or a common feature of the operating system that result in system hardening against techniques."
}
component "control" "Password_Policies" {
  description = "[M1027](https://attack.mitre.org/mitigations/M1027/) Set and enforce secure password policies for accounts."
}
component "control" "Pre-compromise" {
  description = "[M1056](https://attack.mitre.org/mitigations/M1056/) This category is used for any applicable mitigation activities that apply to techniques occurring before an adversary gains Initial Access, such as Reconnaissance and Resource Development techniques."
}
component "control" "Privileged_Account_Management" {
  description = "[M1026](https://attack.mitre.org/mitigations/M1026/) Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root."
}
component "control" "Privileged_Process_Integrity" {
  description = "[M1025](https://attack.mitre.org/mitigations/M1025/) Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other process integrity enforcement measures."
}
component "control" "Remote_Data_Storage" {
  description = "[M1029](https://attack.mitre.org/mitigations/M1029/) Use remote security log and sensitive file storage where access can be controlled better to prevent exposure of intrusion detection log data or sensitive information."
}
component "control" "Restrict_File_and_Directory_Permissions" {
  description = "[M1022](https://attack.mitre.org/mitigations/M1022/) Restrict access by setting directory and file permissions that are not specific to users or privileged accounts."
}
component "control" "Restrict_Library_Loading" {
  description = "[M1044](https://attack.mitre.org/mitigations/M1044/) Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software."
}
component "control" "Restrict_Registry_Permissions" {
  description = "[M1024](https://attack.mitre.org/mitigations/M1024/) Restrict the ability to modify certain hives or keys in the Windows Registry."
}
component "control" "Restrict_Web-Based_Content" {
  description = "[M1021](https://attack.mitre.org/mitigations/M1021/) Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc."
}
component "control" "Software_Configuration" {
  description = "[M1054](https://attack.mitre.org/mitigations/M1054/) Implement configuration changes to software (other than the operating system) to mitigate security risks associated to how the software operates."
}
component "control" "SSL/TLS_Inspection" {
  description = "[M1020](https://attack.mitre.org/mitigations/M1020/) Break and inspect SSL/TLS sessions to look at encrypted web traffic for adversary activity."
}
component "control" "Threat_Intelligence_Program" {
  description = "[M1019](https://attack.mitre.org/mitigations/M1019/) A threat intelligence program helps an organization generate their own threat intelligence information and track trends to inform defensive priorities to mitigate risk."
}
component "control" "Update_Software" {
  description = "[M1051](https://attack.mitre.org/mitigations/M1051/) Perform regular software updates to mitigate exploitation risk."
}
component "control" "User_Account_Control" {
  description = "[M1052](https://attack.mitre.org/mitigations/M1052/) Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access."
}
component "control" "User_Account_Management" {
  description = "[M1018](https://attack.mitre.org/mitigations/M1018/) Manage the creation, modification, use, and permissions associated to user accounts."
}
component "control" "User_Training" {
  description = "[M1017](https://attack.mitre.org/mitigations/M1017/) Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction."
}
component "control" "Vulnerability_Scanning" {
  description = "[M1016](https://attack.mitre.org/mitigations/M1016/) Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them."
}
