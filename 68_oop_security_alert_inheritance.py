# 68_oop_security_alert_inheritance.py
# OOP CONCEPT: inheritance, super(), method overriding
#
# A SecurityAlert is the general PARENT class for anything that goes
# wrong. NetworkAlert, MalwareAlert, and PhishingAlert are CHILD
# classes - each one reuses SecurityAlert's setup code via super(),
# then adds its own extra details on top.

from datetime import datetime


class SecurityAlert:
    def __init__(self, title, severity):
        self.title = title
        self.severity = severity   # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def summary(self):
        return f"[{self.severity}] {self.title} ({self.timestamp})"


class NetworkAlert(SecurityAlert):
    def __init__(self, title, severity, source_ip, port):
        super().__init__(title, severity)   # reuse the parent's setup
        self.source_ip = source_ip
        self.port = port

    def summary(self):
        base = super().summary()   # reuse the parent's version first
        return f"{base} | from {self.source_ip} on port {self.port}"


class MalwareAlert(SecurityAlert):
    def __init__(self, title, severity, file_hash):
        super().__init__(title, severity)
        self.file_hash = file_hash

    def summary(self):
        base = super().summary()
        return f"{base} | hash {self.file_hash[:12]}..."


class PhishingAlert(SecurityAlert):
    def __init__(self, title, severity, sender_email):
        super().__init__(title, severity)
        self.sender_email = sender_email

    def summary(self):
        base = super().summary()
        return f"{base} | from {self.sender_email}"


if __name__ == "__main__":
    alerts = [
        NetworkAlert("Repeated failed SSH logins", "HIGH", "203.0.113.66", 22),
        MalwareAlert("Known-bad hash detected", "CRITICAL", "e99a18c428cb38d5f260853678922e03aabbccd"),
        PhishingAlert("Suspicious invoice email", "MEDIUM", "billing@secure-update.example"),
    ]

    print("=== Security Alert Feed ===")
    for alert in alerts:
        print(alert.summary())   # same method name, different extra detail per type

    print("\n--- Relationship checks ---")
    net_alert = alerts[0]
    print("NetworkAlert is a SecurityAlert:", isinstance(net_alert, SecurityAlert))
    print("SecurityAlert is a NetworkAlert:", isinstance(SecurityAlert("x", "LOW"), NetworkAlert))

    critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    print(f"\n{critical_count} CRITICAL alert(s) need immediate review.")
