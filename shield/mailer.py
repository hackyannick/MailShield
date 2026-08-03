"""Erzeugen und Versenden der Challenge-/Bestaetigungs-Mails sowie Reinjection.

Aller ausgehender Verkehr laeuft ueber den Bypass-smtpd (reinject_host:reinject_port,
siehe master.cf), damit die Nachrichten NICHT erneut durch den Content-Filter laufen
(Loop-Schutz).
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


def _relay():
    from .config import load_config
    cfg = load_config()
    return cfg.reinject_host, cfg.reinject_port


def build_challenge(cfg, to_addr: str, reply_addr: str, code: str,
                    png: bytes, retry: bool = False) -> EmailMessage:
    """Challenge-Mail mit INLINE CID-eingebettetem CAPTCHA.

    Das Bild wird als multipart/related CID-Teil eingebettet (NICHT als data:-URI,
    da Gmail/o365 diese blockieren). Die Absenderdomain wird aus reply_addr
    abgeleitet (verify+<token>@<domain>), damit die Challenge tenant-rein aus der
    jeweiligen Mandantendomain kommt.
    """
    domain = reply_addr.rsplit("@", 1)[-1]
    label = cfg.domain_labels.get(domain, cfg.challenge_from_name)

    msg = EmailMessage()
    msg["From"] = f"{label} <{reply_addr}>"
    msg["To"] = to_addr
    msg["Reply-To"] = reply_addr
    msg["Subject"] = cfg.challenge_subject + (" (erneute Anfrage)" if retry else "")
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    # RFC 3834 / MS-Header: verhindert, dass andere Auto-Responder zuruckantworten.
    msg["Auto-Submitted"] = "auto-replied"
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Precedence"] = "auto_reply"

    # CAPTCHA als CID-Inline-Bild (data:-URIs werden von Gmail/o365 blockiert).
    cid = make_msgid(domain=domain)      # Form: <id@domain>
    cid_ref = cid[1:-1]                   # ohne spitze Klammern fuer src="cid:..."

    text = (
        "Zustellungsprüfung\n"
        "==================\n\n"
        "Ihre E-Mail wurde vorläufig zurückgehalten. Um sie zuzustellen, öffnen\n"
        "Sie diese Nachricht in einem HTML-fähigen Mail-Programm, lesen Sie den\n"
        "Code aus dem angezeigten Bild ab und ANTWORTEN Sie auf diese Mail. Schreiben\n"
        "Sie den Code in die erste Zeile Ihrer Antwort.\n\n"
        "Kann Ihr Programm das Bild nicht anzeigen, wenden Sie sich bitte auf einem\n"
        "anderen Weg an den Empfänger.\n"
    )

    html = f"""\
<html><head><meta charset="utf-8"></head>
<body style="font-family:Arial,Helvetica,sans-serif;color:#222;max-width:520px">
  <h2 style="margin:0 0 8px">Zustellungsprüfung</h2>
  <p>Ihre E-Mail wurde vorläufig zurückgehalten. Um sie zuzustellen,
     geben Sie bitte den unten abgebildeten Code an.</p>
  <div style="margin:16px 0;padding:12px;border:1px solid #ddd;border-radius:8px;
              background:#fafafa;text-align:center">
    <img src="cid:{cid_ref}" alt="Code" width="{cfg.captcha_width}"
         height="{cfg.captcha_height}"
         style="image-rendering:auto;max-width:100%"/>
  </div>
  <p><strong>ANTWORTEN</strong> Sie einfach auf diese E-Mail und schreiben Sie den
     Code in die <strong>erste Zeile</strong> Ihrer Antwort.</p>
  <p style="color:#777;font-size:12px">Diese Prüfung dient dazu, automatisierte
     Zusendungen von echten Absendern zu unterscheiden. Sie muss nur einmal gelöst
     werden.</p>
</body></html>"""

    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    # Bild als "related" an den HTML-Teil haengen (multipart/related, inline).
    html_part = msg.get_payload()[1]
    html_part.add_related(png, maintype="image", subtype="png", cid=cid)
    return msg


def build_confirmation(cfg, to_addr: str, delivered: int,
                       domain: str | None = None) -> EmailMessage:
    domain = domain or cfg.primary_domain
    label = cfg.domain_labels.get(domain, cfg.challenge_from_name)
    msg = EmailMessage()
    msg["From"] = f"{label} <{cfg.verify_localpart}@{domain}>"
    msg["To"] = to_addr
    msg["Subject"] = cfg.confirmation_subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["Auto-Submitted"] = "auto-replied"
    msg["X-Auto-Response-Suppress"] = "All"
    plural = "n" if delivered != 1 else ""
    msg.set_content(
        "Vielen Dank. Ihre Adresse ist nun freigeschaltet.\n"
        f"{delivered} zurückgehaltene E-Mail{plural} wurde{plural} soeben zugestellt.\n"
    )
    return msg


def send(cfg, msg: EmailMessage) -> None:
    with smtplib.SMTP(cfg.reinject_host, cfg.reinject_port, timeout=30) as s:
        s.send_message(msg)


def reinject_raw(cfg, sender: str, recipients, raw: bytes) -> None:
    """Originalnachricht mit Original-Envelope wieder einspeisen (-> Exchange)."""
    with smtplib.SMTP(cfg.reinject_host, cfg.reinject_port, timeout=30) as s:
        s.sendmail(sender, list(recipients), raw)
