## Author

Student: Hasib Rahman
Email: a57540@alunos.ipb.pt
Lab: OSSEC Host Intrusion Detection System Lab
Polytechnic Institute of Bragança  
Cybersecurity / System Security Lab
Framework: Labtainers (Naval Postgraduate School)

# OSSEC Host Intrusion Detection System Lab

> A hands-on Labtainers exercise focused on configuring and testing the OSSEC Host-Based Intrusion Detection System (HIDS).

---

## 📌 Overview

In this lab, I worked with the **OSSEC Host Intrusion Detection System (HIDS)** inside the Labtainers environment. The main goal was to understand how OSSEC monitors systems, generates alerts from logs, performs active responses, and detects suspicious activities through custom rules.

During the lab, I configured OSSEC agents, monitored SSH authentication failures, created custom detection rules, tested active responses, and explored some of the limitations of rule-based intrusion detection systems.

---

## 🖥️ Lab Environment

The lab topology included:

- **OSSEC Server**
- **client1 workstation**
- **webserver**

The lab was started from the Labtainers environment using:

```bash
labtainer ossec
```

---

# 1. Configuring OSSEC Agent for client1

The first task was connecting the `client1` machine to the OSSEC server.

## On the OSSEC Server

I opened the agent management utility:

```bash
sudo su
/var/ossec/bin/manage_agents
```

### Added a new agent

- Name: `client1`
- IP: `172.0.0.3`

Then I extracted the generated key for the agent.

---

## On client1

I imported the generated key:

```bash
sudo su
/var/ossec/bin/manage_agents
```

Selected:

```text
I → Import key
```

After importing the key, I restarted OSSEC on both systems:

```bash
systemctl restart ossec
```

---

# 2. Monitoring Alerts

To observe alerts in real time, I opened another terminal:

```bash
moreterm.py ossec ossec
```

Then monitored the alert log:

```bash
sudo su
tail -f /var/ossec/logs/alerts/alerts.log
```

I triggered authentication-related events on `client1` using:

```bash
sudo su
exit
sudo su
```

These actions generated alerts on the OSSEC server.

---

# 3. Adding the Web Server Agent

Next, I connected the web server to OSSEC.

## On the OSSEC Server

```bash
/var/ossec/bin/manage_agents
```

Added:

- Name: `webserver`
- IP: `172.0.0.4`

Extracted the generated key.

---

## On the Web Server

The CentOS web server uses a slightly different command:

```bash
/var/ossec/bin/manage_agent
```

Imported the key and restarted the service:

```bash
systemctl restart ossec-hids
```

---

# 4. SSH Authentication Failure Alerts

From `client1`, I attempted SSH login with incorrect credentials:

```bash
ssh root@172.0.0.4
```

After several failed attempts, OSSEC generated an alert similar to:

```text
Rule: 5720 (level 10) -> 'Multiple SSHD authentication failures.'
```

---

# 5. Active Response Testing

OSSEC was configured with active response enabled.

After repeated failed SSH attempts, the web server automatically blocked traffic from `client1`.

I verified the firewall rule using:

```bash
iptables -L
```

This demonstrated how OSSEC can automatically respond to suspicious activities.

---

# 6. Monitoring Changes to Listening Ports

The next task involved monitoring open network ports on the web server.

## Modified `ossec.conf`

On the web server:

```bash
nano /var/ossec/etc/ossec.conf
```

Added:

```xml
<localfile>
  <log_format>full_command</log_format>
  <command>netstat -tan |grep LISTEN|grep -v 127.0.0.1</command>
  <frequency>5</frequency>
</localfile>
```

Restarted the service:

```bash
systemctl restart ossec-hids
```

---

## Triggering the Alert

I opened a temporary listening port:

```bash
nc -l 22345
```

OSSEC detected the change and generated an alert indicating that listening ports had changed.

After closing the port using `Ctrl+C`, another alert was generated.

---

# 7. Monitoring Web Resource Access

## Updating Apache Log Paths

The Apache logs were located in:

```bash
/var/log/httpd/
```

I updated the log locations inside:

```bash
/var/ossec/etc/ossec.conf
```

Configured entries:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/httpd/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/httpd/error.log</location>
</localfile>
```

Restarted the service:

```bash
systemctl restart ossec-hids
```

---

# 8. Creating Custom Rules

## Rule for Detecting Access to `plan.html`

I edited:

```bash
/var/ossec/rules/local_rules.xml
```

Added:

```xml
<rule id="140234" level="7">
  <if_sid>31100,31108</if_sid>
  <url_pcre2>plan.html</url_pcre2>
  <description>Accessed the business plan.</description>
</rule>
```

Restarted OSSEC:

```bash
systemctl restart ossec
```

---

## Testing the Rule

From `client1`:

```bash
curl 172.0.0.4/plan.html
```

And:

```bash
curl "172.0.0.4/plan.html?"
```

Both generated alerts successfully.

---

# 9. Detecting Failed Attempts

To detect failed attempts to access protected pages, I added another rule:

```xml
<rule id="140235" level="7">
  <if_sid>31101</if_sid>
  <url_pcre2>plan</url_pcre2>
  <description>Attempt to access the business plan.</description>
</rule>
```

---

## Testing Failed Access Detection

Executed:

```bash
curl 172.0.0.4/plan9.html
```

This generated the alert:

```text
Attempt to access the business plan.
```

Meanwhile:

```bash
curl 172.0.0.4/about.html
```

did not generate any alert.

---

# 10. Testing with wget

I repeated the tests using `wget` instead of `curl`:

```bash
wget 172.0.0.4/plan.html
```

Some alerts did not trigger as expected.

This demonstrated an important limitation of rule-based IDS systems:

> Different clients and request formats can bypass existing detection rules if the rules are not comprehensive enough.

---

# 11. Security Considerations

I explored the OSSEC binaries and running processes:

```bash
ps aux | grep ossec
```

And inspected dependencies:

```bash
ldd ossec-logcollector
```

I observed that several OSSEC components run with root privileges.

This raises an important security consideration:

- IDS systems increase monitoring capability
- But they also introduce additional privileged code into the system
- Active responses themselves can potentially be abused

---

# 12. Abuse of Active Response

One important observation from this lab was that active response mechanisms can unintentionally create denial-of-service situations.

For example:

- Repeated failed SSH attempts from `client1`
- Automatically trigger firewall blocking
- Prevent legitimate communication temporarily

This highlights the trade-off between automated defense and system availability.

---

# 13. Conclusion

This lab provided practical experience with:

- Configuring OSSEC agents
- Monitoring system and web logs
- Creating custom intrusion detection rules
- Understanding active response mechanisms
- Exploring limitations of rule-based IDS systems

Overall, the exercise demonstrated how host-based intrusion detection systems can improve visibility into system activity while also introducing operational and security trade-offs.

---

# 📚 References

- https://www.ossec.net/docs/
- https://wazuh.com/
- https://nps.edu/web/c3o/labtainers

---


