"""Konfiguration fuer MailShield.

Laedt die YAML-Konfiguration (Standard: /opt/mailshield/config.yaml, ueberschreibbar
per Umgebungsvariable MAILSHIELD_CONFIG) und stellt sie als Objekt mit sinnvollen
Defaults bereit.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise SystemExit("PyYAML fehlt: pip install pyyaml") from e


DEFAULT_PATH = "/opt/mailshield/config.yaml"


@dataclass
class Config:
    # Speicher
    db_path: str = "/var/lib/mailshield/state.db"
    quarantine_dir: str = "/var/lib/mailshield/quarantine"

    # Domains
    domains: List[str] = field(default_factory=lambda: ["hackdv.com", "sled-compliance.com"])
    primary_domain: str = "hackdv.com"
    verify_localpart: str = "verify"
    # False (Default): Challenges kommen von der FESTEN Adresse verify@<domain>.
    #   Der Empfaenger-Provider sieht dann immer denselben Absender und kann
    #   Reputation aufbauen ("Kein Spam"-Klicks wirken dauerhaft). Die Zuordnung
    #   der Antwort laeuft ueber die Message-ID der Challenge (In-Reply-To/
    #   References) mit Fallback auf die Absenderadresse.
    # True: alte Variante mit verify+<token>@<domain> (Subadressierung).
    use_token_address: bool = False

    # Reinjection / Bypass-smtpd (siehe master.cf)
    reinject_host: str = "127.0.0.1"
    reinject_port: int = 10026

    # CAPTCHA
    captcha_length: int = 6
    captcha_width: int = 280
    captcha_height: int = 90

    # Challenge-Mail
    challenge_from_name: str = "Zustellungsprüfung"
    challenge_subject: str = "Bestätigung erforderlich, um Ihre E-Mail zuzustellen"
    # Optionaler Anzeigename je Mandant/Domain (From der Challenge). Fallback:
    # challenge_from_name. Beispiel: {"hackdv.com": "hackdv.com", ...}
    domain_labels: Dict[str, str] = field(default_factory=dict)
    max_attempts: int = 3
    send_confirmation: bool = True
    confirmation_subject: str = "Vielen Dank - Ihre E-Mail wurde zugestellt"
    # Ueberschrift der Erfolgs-/Freischaltungsmail (gruener Haken)
    confirm_heading: str = "Freigeschaltet"
    # Harte Blacklist: Betreff, Ueberschrift und Text der Ablehnungsmail (rotes Kreuz)
    reject_subject: str = "Ihre E-Mail wurde abgewiesen"
    reject_heading: str = "Gesperrt"
    # Optionale Fusszeile unter allen automatischen Mails (leer = aus)
    footer_text: str = ""
    reject_message: str = (
        "Ihre E-Mail wurde von MailShield verworfen und geloescht. Sie haben sich "
        "nicht an die Regeln gehalten und wurden gesperrt. Bitte verwenden Sie andere "
        "Kommunikationswege."
    )

    # Backscatter-/Loop-Schutz
    null_sender_markers: List[str] = field(
        default_factory=lambda: ["", "<>", "mailer-daemon", "postmaster"]
    )
    max_challenges_per_hour: int = 200
    # Aufbewahrung: Quarantaene-Mails + verwaiste 'waiting'-Absender aelter als
    # so viele Tage werden von 'cleanup' entfernt.
    retention_days: int = 30

    # Dynamische Eskalation
    escalation_enabled: bool = False
    suspicion_patterns: List[str] = field(
        default_factory=lambda: [
            r"(?i)auto[- ]?reply",
            r"(?i)ticket\s*#?\d+",
            r"(?i)do not reply",
        ]
    )


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("MAILSHIELD_CONFIG", DEFAULT_PATH)
    data = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    cfg = Config()
    for key, value in data.items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)
    if cfg.primary_domain not in cfg.domains:
        cfg.domains.append(cfg.primary_domain)
    return cfg
