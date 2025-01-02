### THM-TacticalDetection: Writeup for TryHackMe Tactical Detection  
By **Ramyar Daneshgar**

---

This repository showcases a methodical approach to tactical threat detection, utilizing **Sigma rules**, **tripwires**, and **purple teaming** to strengthen detection mechanisms for **Indicators of Compromise (IOCs)** and **Indicators of Attack (IOAs)**. The focus is on implementing vendor-agnostic, actionable rules and leveraging adversary simulations to refine an organization’s security posture.

---

### **Walkthrough**

#### **Unique Threat Intel**  
The first step involved translating raw threat intelligence into actionable detection rules. This task focused on IOCs such as `bad3xe69connection.io` and related domains `kind4bad.com` and `nic3connection.io`. These domains were identified as malicious indicators based on prior incident data. The objective was to operationalize this intelligence by detecting unauthorized executable downloads originating from these domains.

To achieve this, I authored a Sigma rule:  
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
IOCs are foundational to modern detection strategies, representing traces of adversary activity. By encoding IOCs into structured, vendor-agnostic rules, they can be leveraged across multiple platforms (e.g., SIEMs like Elastic or Splunk) to detect re-infection attempts or malicious activity. This enhances threat visibility without the need to reinvent the wheel for every tool in the stack.

---

#### **Publicly Generated IOCs**  
In this step, I worked with community-provided Sigma rules for two significant vulnerabilities: **Follina-MSDT (CVE-2022-30190)** and **Log4j**. These rules encapsulate known adversary behaviors, enabling proactive detection.

- **Follina-MSDT Rule**:  
  This rule focused on detecting suspicious executions of `msdt.exe`, a process often exploited via malicious Office documents.  
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

- **Log4j Rule**:  
  Designed to identify suspicious shell executions spawned by Java processes, which are indicative of Log4j exploitation.  

Using **Uncoder**, I transformed these Sigma rules into SIEM-specific queries, such as this Elastic Stack filter for Follina:  
```json
{
  "filter": {
    "term": { "process.name": "msdt.exe" }
  }
}
```

**Why This Matters**:  
Public IOCs allow organizations to leverage collective threat intelligence, reducing time-to-detection for emerging vulnerabilities. Translating these rules into platform-specific queries ensures compatibility while enabling rapid deployment. This step highlights the importance of continuously updating detection mechanisms based on new threat intelligence.

**Key Command**:  
```bash
python uncoder.py --input sigma_rule.yml --output elasticsearch
```

---

#### **Tripwires**  
Tripwires are a proactive detection mechanism, often deployed to monitor sensitive files or directories. For this task, I created a file named **“Secret Document”** and configured it as a high-fidelity indicator by enabling auditing to log all access attempts.

1. **Configure Auditing**:  
   - Enabled **Audit Object Access** via `gpedit.msc` to capture both successful and failed file access attempts.  

2. **Apply Tripwire to the Target File**:  
   - Right-clicked on the file → `Properties > Security > Advanced > Auditing`.  
   - Configured auditing for **all users** to track **Read** and **Write** actions.

3. **Monitor Logs**:  
   - Used Event Viewer to analyze:
     - **Event ID 4663**: Logged access attempts.
     - **Event ID 4656**: Handle requests.
     - **Event ID 4658**: Handle closures.

**Command to Simulate Access**:  
```cmd
type "C:\Users\Administrator\Desktop\Secret Document.txt"
```

**Why This Matters**:  
Tripwires create "high-value" detection opportunities by targeting assets that should never be accessed under normal conditions. This strategy minimizes noise while increasing the likelihood of detecting unauthorized activity, such as insider threats or lateral movement by adversaries.

---

#### **Purple Teaming**  
Purple teaming integrates offensive (red team) tactics with defensive (blue team) strategies to assess and refine detection capabilities. By simulating real-world attack scenarios, I validated the effectiveness of the detection rules and identified gaps in visibility.

- **Tempest Room**:  
  Simulated an attack chain from start to finish, collecting logs and artifacts for analysis. This exercise demonstrated how adversarial actions appear in system logs, helping refine detection rules.

- **Follina-MSDT Room**:  
  Focused on the exploitation of CVE-2022-30190. Logs from this simulation were analyzed to identify opportunities for improving detection coverage.

**Why This Matters**:  
Purple teaming shifts the focus from passive monitoring to active validation. It ensures that detection mechanisms align with adversary TTPs (Tactics, Techniques, and Procedures) and provides a feedback loop for continuous improvement.

