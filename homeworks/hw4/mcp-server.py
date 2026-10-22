import ipaddress
import json

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cybersecurity-investigator")


@mcp.tool()
def analyze_ip(ip_address: str):
    """Classify an IP address; this does not check its threat reputation."""

    try:
        address = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return json.dumps({
            "error": "Invalid IP address",
            "input": ip_address,
        }, indent=2)

    if address.is_loopback:
        category = "loopback"
        assessment = "The address refers to the local host."
    elif address.is_link_local:
        category = "link-local"
        assessment = "The address is intended for a local network link."
    elif address.is_private:
        category = "private"
        assessment = "The address belongs to a private IP range."
    elif address.is_global:
        category = "public"
        assessment = (
            "The address is globally routable. "
            "This does not mean it is malicious."
        )
    else:
        category = "special-purpose or non-global"
        assessment = "The address is not globally routable."

    return json.dumps({
        "ip_address": str(address),
        "version": f"IPv{address.version}",
        "classification": category,
        "assessment": assessment,
        "limitation": "No reputation check was performed.",
    }, indent=2)


@mcp.tool()
def get_mitigation(advice_type: str):
    """Return defensive mitigation recommendations for an event type."""

    event = event_description.strip()

    if not event:
        return "Please provide a security event description"
    
    text = event.lower()
    categories = []
    steps = []

    if any(word in text for word in (
        "login", "sign-in", "sign in", "authentication", "password"
    )):
        categories.append("authentication")
        steps.extend([
            "Review authentication logs and timestamps.",
            "Confirm whether the account owner recognizes the activity.",
            "Check for unusual devices, locations, and repeated failures.",
        ])
    if any(word in text for word in(
        "http", "web", "request", "url", "iis", "nginx"
    )):
        categories.append("web traffic")
        steps.extend([
            "Correlate web logs with application and firewall logs.",
            "Review request paths, response codes, and request frequency.",
        ])
    if any(word in text for word in(
        "malware", "ransomware", "endpoint", "process"
    )):
        categories.append("endpoint security")
        steps.extend([
            "Follow your organization's incident-response procedure.",
            "Preserve relevant endpoint logs and telemetry.",
        ])
    
    if not categories:
        categories.append("general security event")
        steps.extend([
            "Record the event time and affected system or account.",
            "Correlate the event with relevant system and network logs.",
        ])

    steps.extend([
        "Validate findings before drawing conclusions.",
        "Escalate credible incidents according to security policy.",
    ])

    return json.dumps({
        "event" : event,
        "possible_categories" : categories,
        "recommended_checks" : list(dict.fromkeys(steps)),
        "warning": "These are suggestion, not a confirmed diagnosis"
    })

def get_mitigiation(advice_type: str):
    """Return defensive mitigiation recommendations for an event type"""
    category = advice_type.strip().lower()

    guidance = {
        "suspicious login": [
            "Confirm with the account owner through a separate, trusted "
            "channel (not a reply to the alert or the login session).",
            "If unauthorized, revoke all active sessions, tokens, and API "
            "keys, then force a password reset.",
            "Enforce phishing-resistant MFA (FIDO2/passkeys) and check for "
            "attacker-registered MFA devices.",
            "Review audit logs for changes made during the session: mail "
            "forwarding rules, new app consents, role or group changes.",
            "Check whether the same source IP or credentials targeted other "
            "accounts (password spraying or credential stuffing).",
            "Add lockout, conditional-access, or impossible-travel rules "
            "to catch repeat attempts.",
        ],
        "web traffic": [
            "Preserve web server, WAF, load balancer, and firewall logs "
            "before they rotate.",
            "Identify targeted endpoints and parameters; look for injection, "
            "path traversal, or scanning patterns.",
            "Check whether any malicious requests succeeded (2xx/5xx "
            "responses, unexpected data in responses, new files on disk).",
            "Patch or reconfigure the affected application or component, "
            "and remove unnecessarily exposed endpoints.",
            "Apply approved WAF rules, rate limiting, or IP blocking as "
            "short-term containment.",
            "Rotate any secrets or credentials the application may have "
            "exposed.",
        ],
        "malware": [
            "Activate the incident-response plan and notify the security "
            "team immediately.",
            "Isolate affected hosts from the network (EDR isolation or "
            "disconnect) when authorized; avoid powering them off so "
            "memory evidence is kept.",
            "Collect evidence: memory image, disk image, process list, "
            "network connections, and file hashes.",
            "Scope the incident by searching for the same indicators "
            "(hashes, domains, IPs) across other endpoints.",
            "Reset credentials used on affected hosts, prioritizing "
            "privileged and service accounts.",
            "Rebuild or restore from known-good backups only after the "
            "initial access vector is found and closed.",
        ],
        "general": [
            "Preserve relevant logs and evidence before making changes.",
            "Build a timeline: first seen, affected systems and accounts, "
            "and actions taken.",
            "Verify findings with a second data source before acting.",
            "Assess severity and business impact to set priority.",
            "Contain the issue, remediate the root cause, then monitor for "
            "recurrence.",
            "Document lessons learned and update detections and procedures.",
        ],
    }

    # Match the category names returned by get_mitigation's classifier.
    aliases = {
        "authentication": "suspicious login",
        "login": "suspicious login",
        "endpoint security": "malware",
        "ransomware": "malware",
        "general security event": "general",
    }
    category = aliases.get(category, category)

    recommendations = guidance.get(category, guidance["general"])

    return json.dumps({
        "requested_category" : advice_type,
        "mitigations" : recommendations
    }, indent = 2)

if __name__ == "__main__":
    mcp.run(transport = "stdio")
