# Exposed IoT Posture and Operational Impact Hunt

### Why now

Unmanaged smart hardware often lacks the security updates necessary to withstand modern exploits. In a recent analysis, [ESET Research — My IoT devices are no longer supported – is my smart home safe?](https://www.welivesecurity.com/en/internet-of-things/iot-devices-no-longer-supported-smart-home-safe/) details how end-of-life IoT devices represent a permanent and unpatchable attack surface. These devices frequently sit in sensitive network segments yet receive little to no monitoring once the manufacturer stops providing support. This hunt provides a structured way to identify these devices and verify their integrity.

### The hypothesis

An adversary exploits unpatched vulnerabilities in end-of-life IoT devices to establish a persistent presence. This activity leaves evidence through rare process execution on identified smart hardware, unauthorized external exposure of management ports to the public internet, and failing operational states in the IoT control plane.

### How the hunt flows

The hunt begins by scoping the enrolled estate for devices that identify as IoT hardware. It uses a keyword-based query against the local device inventory to find hosts with names or hardware vendors matching profiles like cameras, gateways, and controllers. This ensures the subsequent, more intensive behavioral checks focus only on relevant hardware.

Once scoped, the hunt fans out to correlate evidence across three independent surfaces. The first query identifies rare processes on the IoT hosts, looking for binaries seen on three or fewer devices. Simultaneously, the hunt checks external asset data for management interfaces like RTSP or HTTP exposed on the public internet. A third check examines the Azure IoT Hub control plane to find hubs in an inactive or failed state, which can signal device-level failures or takeover.

An analyst then triages these combined results. By weighing an internal process anomaly against an external exposure finding, the analyst determines if a device acts as a beachhead. If the hunt confirms a compromise, the workflow provides instructions to isolate the device at the network level and revoke its cloud credentials.

### What the hunt cannot see

This hunt relies on existing endpoint and cloud telemetry. If an IoT device does not run an agent or report to the internal inventory, it remains invisible to the process-level checks. Furthermore, while the hunt identifies failed states in the IoT Hub, it cannot see specific malicious commands sent to devices without CloudToDevice diagnostic logging enabled. We recommend passive network monitoring to identify these silent, unmanaged devices by their MAC addresses.

### How to run it

This hunt is available as an open hunt.md playbook. You can import the playbook into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. Because this hunt correlates disparate surfaces—endpoint, external exposure, and cloud control planes—it provides a more complete view of IoT risk than a single detection rule focused on a specific CVE.
