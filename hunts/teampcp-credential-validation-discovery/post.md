# Hunt for TeamPCP post-compromise credential validation and discovery

### Why this hunt matters
The recent research by Wiz, Tracking TeamPCP: post-compromise attacks seen in the wild (https://www.wiz.io/blog/tracking-teampcp-investigating-post-compromise-attacks-seen-in-the-wild), details how attackers use supply chain compromises to harvest secrets. Once an adversary gains access to a developer workstation or CI/CD runner, they move quickly. They validate the stolen credentials and map the cloud environment before defenders even realize a package was compromised. We built this hunt to catch that transition from the local environment to the cloud control plane.

### The hypothesis
An adversary validates stolen cloud credentials and enumerates cloud infrastructure using offensive tools like TruffleHog or specialized Boto3 scripts following a supply chain compromise.

### How the hunt flows
The hunt begins with a scoping exercise across the software inventory. It identifies hosts running packages targeted by TeamPCP, such as Trivy, KICS, LiteLLM, or Telnyx. These hosts represent the potential beachheads where an adversary likely harvested secrets. This step narrows the search space for the rest of the investigation.

Once the hunt establishes the host scope, it pivots into a parallel analysis of network and authentication logs. One query checks for sign-ins from known TeamPCP IP addresses and VPN exit nodes. Simultaneously, another query searches for HTTP traffic containing user-agent signatures for offensive tools like TruffleHog or Kali-based Boto3 scripts. These signals provide the first direct evidence of credential validation attempts.

The final data collection phase moves to the cloud control plane. The hunt uses AWS IAM Access Advisor to find principals that recently accessed a broad range of discovery-related services, including IAM, S3, Secrets Manager, and RDS. By filtering for the specific principals involved in the suspicious sign-ins found earlier, the hunt highlights identities exhibiting unusual enumeration patterns.

An automated agent then correlates these independent signals. It looks for a sequence where a host running a vulnerable package connects to a known-bad IP, followed by an AWS identity from that same IP performing wide-scale service discovery. This correlation allows an analyst to distinguish between legitimate developer activity and a compromise.

### What the hunt cannot see
This hunt relies on AWS IAM Access Advisor, which indicates whether a service was accessed but does not provide object-level details. We cannot see exactly which S3 objects or Secrets Manager values the adversary retrieved through these queries. To determine the full extent of data exfiltration, an analyst must perform a follow-up forensic audit of CloudTrail logs. Additionally, if the adversary rotates to a fresh VPN exit node not included in our known IP list, the hunt relies on the rarity of the authentication origin rather than a direct threat intelligence match.

### How to run it
This hunt is an open-source playbook in the hunt.md format. You can import it into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the necessary SQL queries and logic to guide an analyst through the triage process and automate the revocation of compromised credentials if needed.
