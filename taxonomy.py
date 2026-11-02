"""Exact taxonomy used by the CPS incident-classification demo."""

TAXONOMY = {
    "Functional Correctness": {
        "Safety": {
            "definition": "Absence of hazardous physical states, damage, injury, or unsafe operation.",
            "phrases": [
                "unsafe state", "hazardous condition", "risk to life", "loss of life",
                "physical damage", "equipment damage", "safety system", "unsafe shutdown"
            ],
            "keywords": ["injury", "fatality", "explosion", "fire", "hazard", "unsafe", "damage"],
        },
        "Liveness": {
            "definition": "A required operation or progress condition eventually completes.",
            "phrases": [
                "failed to complete", "never completed", "command not executed",
                "process stalled", "unable to complete", "no progress"
            ],
            "keywords": ["deadlock", "stalled", "unfinished", "blocked"],
        },
        "Reachability": {
            "definition": "An attacker or system state reaches a protected component or forbidden state.",
            "phrases": [
                "gained access", "unauthorized access", "remote access",
                "lateral movement", "reached scada", "accessed scada",
                "accessed control system", "penetrated the network",
                "compromised the network", "compromised a server",
                "accessed the server", "accessed the system"
            ],
            "keywords": ["intrusion", "penetrated", "breached", "accessed", "foothold"],
        },
        "Timing Constraints": {
            "definition": "A real-time response, deadline, synchronization, or latency constraint is violated.",
            "phrases": [
                "missed deadline", "delayed response", "real-time deadline",
                "timing violation", "response-time violation", "time constraint"
            ],
            "keywords": ["latency", "deadline", "timing", "synchronization"],
        },
        "Hybrid Dynamics": {
            "definition": "Cyber actions adversely manipulate or destabilize continuous physical dynamics.",
            "phrases": [
                "voltage instability", "frequency deviation", "pressure manipulation",
                "flow manipulation", "physical process manipulation", "setpoint manipulation",
                "sensor reading manipulation", "actuator manipulation"
            ],
            "keywords": ["voltage", "frequency", "pressure", "temperature", "setpoint", "actuator"],
        },
    },
    "Information Protection": {
        "Confidentiality": {
            "definition": "Information is disclosed, copied, or obtained by an unauthorized party.",
            "phrases": [
                "data theft", "data was stolen", "data were stolen", "stolen data",
                "data exfiltration", "data was exfiltrated", "data were exfiltrated",
                "unauthorized disclosure", "copied files", "internal data stolen",
                "information was stolen", "information stolen", "data breach"
            ],
            "keywords": ["stolen", "exfiltrated", "leaked", "exposed", "disclosed", "copied"],
        },
        "Integrity": {
            "definition": "Data, firmware, software, commands, configuration, or devices are modified or destroyed.",
            "phrases": [
                "files were deleted", "files deleted", "data was wiped", "data were wiped",
                "firmware was corrupted", "firmware corrupted", "factory reset",
                "configuration was modified", "destructive attack", "destructive cyberattack",
                "attacks were destructive", "attack was destructive", "were destructive",
                "systems were wiped", "tampered with", "undocumented devices",
                "rogue communication devices",
                "undocumented communication devices", "unapproved hardware"
            ],
            "keywords": [
                "modified", "altered", "corrupted", "wiped", "deleted",
                "tampered", "falsified", "manipulated", "destroyed", "destructive"
            ],
        },
        "Availability": {
            "definition": "An authorized user, service, system, communication path, or resource becomes unavailable.",
            "phrases": [
                "service interruption", "services were disrupted", "systems were disrupted", "services disrupting",
                "website availability", "loss of service", "loss of access",
                "loss of communication", "systems were disconnected", "disconnect all systems",
                "forced to disconnect", "power outage", "electricity outage",
                "remained unavailable", "became unavailable", "taken offline",
                "electricity supply", "scada systems", "operational technologies",
                "oil transport", "telecommunications systems"
            ],
            "keywords": [
                "unavailable", "offline", "outage", "disrupted", "disrupting", "disruption",
                "inaccessible", "disconnected", "shutdown", "interrupted", "downtime"
            ],
        },
        "Authenticity": {
            "definition": "The identity or origin of a user, device, message, command, or artifact cannot be trusted.",
            "phrases": [
                "forged identity", "fake certificate", "spoofed command",
                "impersonated user", "masqueraded as", "credential impersonation"
            ],
            "keywords": ["impersonated", "spoofed", "forged", "masqueraded", "counterfeit"],
        },
        "Authorization": {
            "definition": "An entity performs an action or accesses a resource without permitted privileges.",
            "phrases": [
                "unauthorized action", "without authorization", "without permission",
                "privilege escalation", "administrative access", "access control bypass",
                "unauthorized command", "unauthorized administrator"
            ],
            "keywords": ["unauthorized", "privilege", "permission", "administrator"],
        },
        "Accountability": {
            "definition": "Actions cannot be traced reliably to responsible entities because evidence or auditability is missing.",
            "phrases": [
                "logs were deleted", "logs deleted", "audit trail erased",
                "evidence was destroyed", "forensic evidence destroyed",
                "forensic artifacts removed", "monitoring was disabled"
            ],
            "keywords": ["traceability", "audit trail", "logs", "forensic", "evidence erased"],
        },
        "Non-repudiation": {
            "definition": "The system lacks reliable proof that a specific entity performed an action or sent a message.",
            "phrases": [
                "denied the action", "proof of origin", "cannot verify the transaction",
                "transaction could not be verified", "signature could not be verified"
            ],
            "keywords": ["repudiated", "non-repudiation", "digital signature"],
        },
    },
    "Operational Assurance": {
        "Privacy": {
            "definition": "Personal or personally identifiable information is exposed or improperly processed.",
            "phrases": [
                "personal data", "customer data", "sensitive customer data",
                "personally identifiable information", "identity documents",
                "passport scans", "customer records", "personal information",
                "names and email addresses", "telephone numbers"
            ],
            "keywords": ["privacy", "personal", "customer", "passport", "identity", "email", "phone"],
        },
        "Reliability": {
            "definition": "The system fails to provide correct, stable, or consistent service over time.",
            "phrases": [
                "repeated failures", "unstable operation", "degraded performance",
                "incorrect operation", "intermittent failures", "service instability"
            ],
            "keywords": ["unreliable", "unstable", "intermittent", "malfunction", "degraded"],
        },
        "Resilience": {
            "definition": "The system cannot maintain essential functions, contain disruption, or adapt during attack.",
            "phrases": [
                "unable to contain", "cascading disruption", "essential service failed",
                "failover failed", "redundancy failed", "lost core function",
                "service continuity failed"
            ],
            "keywords": ["cascading", "failover", "redundancy", "continuity"],
        },
        "Recoverability": {
            "definition": "The system cannot be restored promptly and correctly after disruption.",
            "phrases": [
                "weeks to restore", "days to restore", "for weeks", "for several weeks", "restoration took",
                "rebuilding systems", "rebuild the systems", "recovery process",
                "disaster recovery", "systems were restored", "restore operations"
            ],
            "keywords": ["restore", "restored", "restoration", "recovery", "rebuild", "backups"],
        },
        "Compliance": {
            "definition": "A legal, regulatory, policy, audit, or mandatory reporting obligation is violated.",
            "phrases": [
                "regulatory violation", "mandatory reporting", "legal requirement",
                "compliance violation", "reporting obligation", "data protection authority"
            ],
            "keywords": ["non-compliance", "regulatory", "compliance", "gdpr", "nis2"],
        },
        "Explainability": {
            "definition": "An automated or algorithmic system action cannot be explained or justified.",
            "phrases": [
                "unexplained automated decision", "unable to explain the decision",
                "lack of transparency", "opaque decision", "black-box decision"
            ],
            "keywords": ["unexplained", "opaque", "explainability", "black-box"],
        },
    },
}

PROPERTY_TO_PARENT = {
    prop: parent
    for parent, properties in TAXONOMY.items()
    for prop in properties
}

STATUS_ORDER = {
    "CONFIRMED": 4,
    "CLAIMED": 3,
    "POTENTIAL": 2,
    "UNAFFECTED": 1,
    "UNKNOWN": 0,
}
