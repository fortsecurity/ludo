**🧪 Project Ludo: Active AI Deception & Threat Intelligence**

Your big, fluffy AI Deception Monster (for training and demo purposes only)

<img width="200" height="200" alt="ludo" src="https://github.com/user-attachments/assets/d74780ff-24fe-4663-96c6-64c5b4028714" />


Project Ludo is a hands-on, Infrastructure-as-Code (IaC) deployment designed to teach Advanced Cloud Security and Active Defense. It deploys a memory-resident honeypot that leverages Google's Gemini 3.5 Flash LLM to actively engage, stall, and deanonymize attackers, mapping their behaviors directly to the MITRE ATLAS framework.

📖 Project Overview & Core Concepts
When deploying this environment, you will explore four foundational pillars of modern cloud defense:

**Active Deception (The Honeytoken Rule):** Instead of signaling to an attacker that their prompt was flagged with a standard refusal block, Ludo actively stalls them. It dangles synthetic financial data to extract deanonymizing personal contact details (e.g., demanding a personal 2FA email).

**Infrastructure as Code (IaC):** Leveraging Terraform, the entire environment (IAM identities, routing sinks, datasets, firewalls, and compute) is built and destroyed deterministically in minutes.

**Cloud Native OPSEC (Zero-Disk Logging):** The application uses direct google-cloud-logging memory-to-API streaming. If an attacker drops a web shell or achieves local execution, there are no text log files on the disk revealing the detection mechanisms.

**The Telemetry Lifecycle:** Trace the lifecycle of an attack string—moving from a raw adversarial prompt, parsed into a JSON object in memory by the LLM, crossing directly into the Cloud Logging API, and natively structuring into a BigQuery analytical database.

For more deception shenanigans, contact team@fortsecurity.io
