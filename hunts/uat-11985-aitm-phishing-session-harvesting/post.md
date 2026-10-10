# UAT-11985 AI-Assisted AitM Phishing and Session Harvesting

### Why Now

Cisco Talos recently reported on a sophisticated campaign they track as [UAT-11985](https://blog.talosintelligence.com/uat-11985/). The adversary targets research personnel with AI-assisted event lures to deliver a real-time adversary-in-the-middle (AitM) phishing kit. This kit specializes in harvesting Google session tokens to bypass multi-factor authentication (MFA). Because the kit uses dynamic URIs and WebSocket orchestration, traditional static indicators often fail to detect a successful compromise.

### The Hypothesis

An adversary uses an AI-assisted AitM phishing framework to harvest authenticated Google sessions from research personnel. They identify targets via real-time WebSocket orchestration and specific success-page artifacts left in browser history and network logs.

### How the Hunt Flows

The hunt first scopes the estate to identify hosts with web browsers. This baseline narrows the focus to devices capable of executing the phishing kit's obfuscated JavaScript and communicating with the AitM proxy.

In the second phase, the hunt searches for early evidence of initial access. It looks for HTTP requests to the specific success-page path used by the UAT-11985 kit, such as operation-success.html. Simultaneously, it baselines DNS activity to find rare resolutions that might represent the actor's redirect infrastructure.

An analyst then examines the impact and command-and-control (C2) synchronization. The hunt identifies persistent outbound TCP/443 connections, which are consistent with the WebSocket traffic the kit uses to sync authentication states in real-time. It also reviews Google sign-in logs to find successful authentications originating from external infrastructure or anomalous geolocations.

Finally, the hunt correlates the delivery of the phishing assets with the subsequent session usage. This synthesis provides a high-confidence verdict by proving that a user did not just land on a lure, but actually completed the authentication flow and had their session hijacked.

### What the Hunt Cannot See

This hunt has two primary blind spots. If the organization does not enroll its identity provider (IdP) logs into the central telemetry surface, the hunt cannot see if an actor uses a stolen session to sign in from their own infrastructure. Additionally, standard network logs capture the initial WebSocket upgrade request but do not inspect the frames within the encrypted channel. An analyst sees the persistent connection but not the specific commands sent during the MFA orchestration.

### How to Run the Hunt

This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. It requires access to software inventory, DNS resolution data, HTTP traffic logs, and identity sign-in telemetry. Because this is a hunt, it focuses on the chain of evidence across multiple surfaces rather than a single static alert.
