### THM-TacticalDetection: Writeup for TryHackMe Tactical Detection  
By **Ramyar Daneshgar**

---

#### **Description**  
This LAB demonstrateD a methodical approach to tactical threat detection, utilizing **Sigma rules**, **tripwires**, and **purple teaming** to strengthen detection mechanisms for **Indicators of Compromise (IOCs)** and **Indicators of Attack (IOAs)**. Each step focuses on operationalizing threat intelligence, implementing proactive detection mechanisms, and refining SOC capabilities through adversary simulation and iterative improvement.

---

### **Walkthrough**

#### **Unique Threat Intel**  
The first step involved translating raw threat intelligence into actionable detection rules. I encountered IOCs such as `bad3xe69connection.io` and related domains `kind4bad.com` and `nic3connection.io`. These were transformed into a **Sigma rule** to detect unauthorized executable downloads from the malicious domains:  

```yaml
title: Executable Download from Suspicious Domains
logsource:
  category: proxy
detection:
  selection:
    c-uri-extension:
      - 'exe'
    r-dns:
      - 'bad3xe69connection.io'
      - 'kind4bad.com'
      - 'nic3connection.io'
  condition: selection
```

**Why This Matters**:  
IOCs are critical for detecting and responding to adversary activity. By encoding them into structured detection rules, I ensured compatibility across SIEM platforms and enabled proactive identification of malicious activity. This step reinforces the importance of turning passive intelligence into actionable capabilities.

**Lessons Learned**:  
- Understanding IOC relationships (e.g., associated domains) enhances detection accuracy.
- Vendor-agnostic formats like Sigma streamline implementation across diverse tools.

---

#### **Publicly Generated IOCs**  
This task focused on leveraging public Sigma rules for two vulnerabilities: **Follina-MSDT (CVE-2022-30190)** and **Log4j**. Using **Uncoder**, I translated Sigma rules into platform-specific queries. For example:  

- **Follina-MSDT Rule** (detecting suspicious `msdt.exe` executions):  
  ```yaml
  title: Suspicious msdt.exe execution - Office Exploit
  detection:
    selection1:
      Image|endswith:
        - 'msdt.exe'
    selection2:
      CommandLine|contains:
        - 'PCWDiagnostic'
    condition: selection1 and selection2
  ```

- **Elastic Stack Query** (transformed Sigma rule):  
  ```json
  {
    "filter": {
      "term": { "process.name": "msdt.exe" }
    }
  }
  ```

**Why This Matters**:  
Leveraging public IOCs reduces the time required to address emerging threats. Translating these rules ensures alignment with the organization’s tools, creating actionable alerts that enhance detection speed and precision.

**Lessons Learned**:  
- Community-driven IOCs provide a foundation for rapid detection against known threats.
- Rules require tuning to align with specific environments, minimizing false positives.

---

#### **Tripwires**  
Tripwires were implemented to detect unauthorized access to sensitive assets. I created a file, **“Secret Document”**, and configured auditing to log all access attempts:  

1. **Configure Auditing**:  
   - Enabled **Audit Object Access** via `gpedit.msc`, logging both successful and failed access attempts.  

2. **Apply File-Specific Auditing**:  
   - Configured the file to monitor **Read** and **Write** actions for all users.  

3. **Monitor Logs**:  
   - Event Viewer tracked relevant Event IDs:  
     - **4663**: File access attempts.  
     - **4656**: Handle requested.  
     - **4658**: Handle closure.  

**Command to Simulate Access**:  
```cmd
type "C:\Users\Administrator\Desktop\Secret Document.txt"
```

**Why This Matters**:  
Tripwires act as high-fidelity detection mechanisms, providing focused monitoring with minimal noise. They are particularly effective for detecting lateral movement or insider threats targeting critical assets.

**Lessons Learned**:  
- Tripwires are invaluable for detecting “unknown unknowns,” where standard rules might fail.
- Consolidating sensitive files into monitored folders simplifies auditing and analysis.

---

#### **Purple Teaming**  
Purple teaming integrated offensive tactics with defensive measures, allowing me to validate detection mechanisms through simulated attacks:  

1. **Tempest Room**:  
   Simulated a complete attack chain, analyzing logs to identify detection gaps and refine rules.  

2. **Follina-MSDT Room**:  
   Focused on exploiting CVE-2022-30190, capturing artifacts to improve rule specificity and reliability.

**Why This Matters**:  
Adversary simulations test the efficacy of detection mechanisms against real-world tactics, techniques, and procedures (TTPs). This iterative process enhances visibility, response capabilities, and overall security posture.

**Lessons Learned**:  
- Purple teaming bridges the gap between offense and defense, highlighting areas for improvement.  
- Simulated attacks validate existing detections while identifying gaps that might otherwise go unnoticed.

---

### **Key Lessons Learned**  
1. **Proactive Detection is Essential**: Default rules provide a baseline, but tailored detection mechanisms ensure actionable insights.  
2. **Collaborate on Intelligence**: Leveraging community-driven IOCs accelerates detection against emerging threats.  
3. **Deploy Focused Monitoring**: Tripwires add depth to detection strategies, providing early warning for critical asset access.  
4. **Continuously Test and Improve**: Purple teaming validates detections and uncovers gaps, driving iterative improvements in SOC capabilities.
