# THM-TacticalDetection
Writeup for TryHackMe Tactical Detection -  leveraging Sigma rules, tripwires, and purple teaming to identify Indicators of Compromise (IOCs) and Indicators of Attack (IOAs).

---

#### Task 1: Unique Threat Intel
During this task, I encountered a simulated scenario with unique IOCs. For example:
- **IOC**: `bad3xe69connection.io` (original malicious domain).
- Related domains: `kind4bad.com` and `nic3connection.io`.

I created a Sigma rule to detect downloads of `.exe` files from these domains:
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
Using Sigma, I transformed these IOCs into vendor-agnostic rules that can be implemented across SIEM solutions.

**Lessons Learned**:
- IOCs can reveal patterns of adversary behavior.
- Sharing and transforming threat intel enhances organizational collaboration.

---

#### Task 2: Publicly Generated IOCs
I worked with two prominent vulnerabilities:
1. **Follina-MSDT**:
   - Sigma Rule Example:
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

2. **Log4j**:
   - Focused on detecting suspicious shells spawned by Java processes.

Using **Uncoder**, I translated Sigma rules into **Elastic Stack** and **Splunk** queries. For example:
- Elastic Stack Query:
  ```json
  {
    "filter": {
      "term": { "process.name": "msdt.exe" }
    }
  }
  ```

**Commands Used**:
- For translation: 
  ```bash
  python uncoder.py --input sigma_rule.yml --output elasticsearch
  ```

---

#### Task 3: Leveraging “Know Your Environment” - Tripwires
I set up a tripwire to monitor access to a **"Secret Document"** on the VM:
1. Enabled **Audit Object Access**:
   - Command: 
     ```cmd
     gpedit.msc
     ```
     Navigate to `Local Policies > Audit Policy > Audit Object Access` and enable both **Success** and **Failure**.

2. Configured auditing on the file:
   - Created a text file named **Secret Document**.
   - Set auditing for all users on activities like **Read** and **Write**.

3. Verified logs using **Event Viewer**:
   - Event ID **4663**: File access attempts.
   - Event ID **4656**: Handle requested.
   - Event ID **4658**: Handle closed.

**Commands**:
- To simulate access: 
  ```cmd
  type "C:\Users\Administrator\Desktop\Secret Document.txt"
  ```

**Lessons Learned**:
- Tripwires are effective for detecting unauthorized access to sensitive data.
- Monitoring tools like **Event Viewer** and **FullEventLogView** simplify log analysis.

---

#### Task 4: Purple Teaming
I explored the concept of **purple teaming**, combining red team offensive tactics with blue team defensive measures. Two rooms highlighted its value:
1. **Tempest Room**:
   - Simulated a complete attack chain to analyze detection gaps.
   - Encouraged reflection on missed detections and opportunities for improvement.

2. **Follina MSDT**:
   - Focused on the exploitation of CVE-2022-30190.
   - Logs and artifacts provided context for refining detection rules.

**Lessons Learned**:
- Purple teaming bridges the gap between offense and defense.
- Simulated attacks are invaluable for validating detection mechanisms.


