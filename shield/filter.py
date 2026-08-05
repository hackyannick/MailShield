"""Content-Filter-Kern.

Wird von Postfix pro Nachricht per pipe aufgerufen:
    run_filter.py <sender> <recipient> [<recipient> ...]   # Mail auf stdin

Entscheidungslogik:
  * Empfaenger = verify+<token>@domain -> CAPTCHA-Antwort pruefen
  * Absender verifiziert               -> an Exchange durchreichen
  * Absender wartet (waiting)          -> still quarantaenen (Loop-Protection)
  * Absender unbekannt                 -> quarantaenen + Challenge senden
  * Null-Sender / Bulk / Auto          -> quarantaenen, KEINE Challenge (Backscatter-Schutz)
"""
from __future__ import annotations

import html as html_lib
import os
import re
import secrets
import sys
import syslog
import time
from email import message_from_bytes
from email.message import Message
from email.utils import parseaddr

from . import captcha, db, mailer
from .config import Config, load_config

EX_TEMPFAIL = 75      # Postfix haelt die Mail und versucht es erneut
EX_UNAVAILABLE = 69


def _log(level: int, msg: str) -> None:
    syslog.syslog(syslog.LOG_MAIL | level, "mailshield: " + msg)


# ------------------------------------------------------------ Hilfsfunktionen

def _new_token() -> str:
    # Hex (nur [0-9a-f]) – ueberlebt das Lowercasing der Empfaengeradresse durch
    # Postfix/parseaddr und enthaelt keine Zeichen, die eine Adresse stoeren.
    return secrets.token_hex(8)


def _is_null_sender(cfg: Config, sender: str) -> bool:
    """Bounce-/Zustellsystem-Absender, die niemals eine Challenge bekommen duerfen.
    Neben dem klassischen Null-Sender erkennt dies auch VERP-Bounce-Adressen
    (bounce+..., msprvs1=...-bounces-..., srs0=..., lange Hex-Localparts), an die
    eine Challenge nur Backscatter erzeugt und die Domain-Reputation schaedigt."""
    s = sender.strip().lower()
    if s in {m.lower() for m in cfg.null_sender_markers}:
        return True
    local = s.split("@", 1)[0]
    if local in {"mailer-daemon", "postmaster"}:
        return True
    # VERP-/Bounce-Muster im Localpart
    if re.match(r"^(bounce|bounces|bounce-|return|prvs|msprvs\d*|srs\d*)[-+=_.]", local):
        return True
    if "bounce" in local and any(c in local for c in "+=-"):
        return True
    # Reine Hex-/Zufalls-Localparts ab 24 Zeichen (Notification-/Tracking-Systeme)
    if len(local) >= 24 and re.fullmatch(r"[0-9a-f]+", local):
        return True
    return False


def _match_verify(cfg: Config, rcpt: str):
    """Erkennt Verify-Empfaenger. Rueckgabe:
         None -> keine Verify-Adresse
         ""   -> feste Adresse verify@<domain> (Zuordnung ueber Message-ID/Absender)
         "<token>" -> Subadressierung verify+<token>@<domain>
    """
    addr = parseaddr(rcpt)[1].lower()
    if "@" not in addr:
        return None
    local, domain = addr.rsplit("@", 1)
    if domain not in [d.lower() for d in cfg.domains]:
        return None
    vl = cfg.verify_localpart.lower()
    if local == vl:
        return ""
    prefix = vl + "+"
    if not local.startswith(prefix):
        return None
    return local[len(prefix):]


def _reply_address(cfg: Config, token: str, domain: str) -> str:
    """Absender-/Reply-Adresse der Challenge. Ohne Token-Adressierung immer
    dieselbe Adresse -> Reputationsaufbau beim Empfaenger-Provider."""
    if cfg.use_token_address:
        return f"{cfg.verify_localpart}+{token}@{domain}"
    return f"{cfg.verify_localpart}@{domain}"


def _referenced_msgids(msg: Message | None):
    """Message-IDs aus In-Reply-To und References einer Antwort."""
    if msg is None:
        return []
    ids = []
    for hdr in ("In-Reply-To", "References"):
        val = msg.get(hdr)
        if val:
            ids.extend(re.findall(r"<[^>]+>", val))
    return ids


def _resolve_pending(cfg: Config, token: str, sender: str, msg: Message | None):
    """Findet den wartenden Absender zu einer Verify-Antwort.
    Reihenfolge: Token (falls vorhanden) -> Message-ID der Challenge -> Absender."""
    if token:
        row = db.find_by_token(token)
        if row:
            return row
    for mid in _referenced_msgids(msg):
        row = db.find_by_msgid(mid)
        if row:
            return row
    row = db.get_sender(sender)
    if row and row["status"] == "waiting":
        return row
    return None


def _recipient_domain_ok(cfg: Config, rcpt: str) -> bool:
    addr = parseaddr(rcpt)[1].lower()
    if "@" not in addr:
        return False
    return addr.rsplit("@", 1)[1] in [d.lower() for d in cfg.domains]


def _safe_recipients(cfg: Config, recipients):
    """App-seitiger Open-Relay-Schutz: nur Empfaenger der geschuetzten Domain(s)
    werden je reinjiziert. Fremde Empfaenger werden NIE weitergereicht – auch dann
    nicht, wenn Postfix (durch Fehlkonfiguration) sie durchgelassen haette."""
    allowed, dropped = [], []
    for r in recipients:
        (allowed if _recipient_domain_ok(cfg, r) else dropped).append(r)
    return allowed, dropped


def _challenge_domain(cfg: Config, recipients) -> str:
    """Tenant-reine Challenge: nutze die Domain des ersten geschuetzten Empfaengers
    (Mandantentrennung), sonst primary_domain als Fallback."""
    domains = [d.lower() for d in cfg.domains]
    for r in recipients:
        addr = parseaddr(r)[1].lower()
        if "@" in addr:
            dom = addr.rsplit("@", 1)[1]
            if dom in domains:
                return dom
    return cfg.primary_domain


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html_lib.unescape(text)


def _is_attachment(part: Message) -> bool:
    return (part.get("Content-Disposition") or "").lower().startswith("attachment")


def _get_text(msg: Message | None) -> str:
    if msg is None:
        return ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not _is_attachment(part):
                return _decode_part(part)
        for part in msg.walk():
            if part.get_content_type() == "text/html" and not _is_attachment(part):
                return _strip_html(_decode_part(part))
        return ""
    body = _decode_part(msg)
    return _strip_html(body) if msg.get_content_type() == "text/html" else body


def _subject(msg: Message | None) -> str:
    return (msg.get("Subject", "") if msg else "") or ""


def _looks_automated(msg: Message | None) -> bool:
    if msg is None:
        return False
    auto = (msg.get("Auto-Submitted") or "").strip().lower()
    if auto and auto != "no":
        return True
    prec = (msg.get("Precedence") or "").strip().lower()
    if prec in {"bulk", "list", "junk", "auto_reply"}:
        return True
    if msg.get("List-Id") or msg.get("List-Unsubscribe"):
        return True
    if msg.get("X-Auto-Response-Suppress"):
        return True
    frm = parseaddr(msg.get("From", ""))[1].lower()
    local = frm.split("@", 1)[0]
    return any(tok in local for tok in ("no-reply", "noreply", "mailer-daemon",
                                        "postmaster", "donotreply"))


def _is_suspicious(cfg: Config, msg: Message | None) -> bool:
    if msg is None:
        return False
    haystack = _subject(msg) + " " + (msg.get("From", "") or "")
    return any(re.search(p, haystack) for p in cfg.suspicion_patterns)


def _extract_answer(msg: Message | None, length: int) -> str | None:
    body = _get_text(msg)
    if not body:
        return None
    lines = []
    for ln in body.splitlines():
        s = ln.strip()
        if s.startswith(">"):
            break
        if re.match(r"(?i)(am|on)\b.*(schrieb|wrote)\s*:", s):
            break
        if s.lower().startswith(("from:", "von:", "-----ursprüngliche",
                                 "-----original")):
            break
        lines.append(s)
    top = " ".join(lines).upper()
    exact = re.findall(r"[A-Z0-9]{%d}" % length, top)
    if exact:
        return exact[0]
    compact = re.sub(r"[^A-Z0-9]", "", top)
    return compact[:length] if len(compact) >= length else (compact or None)


# ------------------------------------------------------------- Quarantaene

def _quarantine(cfg: Config, sender: str, recipients, raw: bytes,
                subject: str) -> int:
    """Rohe Nachricht ablegen + DB-Eintrag. Rueckgabe: 0 ok, sonst EX_TEMPFAIL."""
    try:
        os.makedirs(cfg.quarantine_dir, exist_ok=True)
        fname = f"{int(time.time()*1000)}-{secrets.token_hex(6)}.eml"
        path = os.path.join(cfg.quarantine_dir, fname)
        with open(path, "wb") as fh:
            fh.write(raw)
        db.add_quarantine(sender or "<>", recipients, path, subject)
        return 0
    except OSError as e:
        _log(syslog.LOG_ERR, f"Quarantaene fehlgeschlagen fuer {sender}: {e}")
        return EX_TEMPFAIL


def _relay(cfg: Config, sender: str, recipients, raw: bytes) -> int:
    allowed, dropped = _safe_recipients(cfg, recipients)
    if dropped:
        _log(syslog.LOG_WARNING,
             f"Relay-Schutz: fremde Empfaenger von {sender} verworfen: {dropped}")
    if not allowed:
        _log(syslog.LOG_WARNING,
             f"Relay-Schutz: keine zulaessigen Empfaenger fuer {sender} -> verworfen")
        return 0  # nichts zu tun; Mail nicht als Relay hinausschicken
    try:
        mailer.reinject_raw(cfg, sender, allowed, raw)
        return 0
    except Exception as e:  # smtplib/connection -> spaeter erneut versuchen
        _log(syslog.LOG_ERR, f"Reinject fuer {sender} fehlgeschlagen: {e}")
        return EX_TEMPFAIL


def _release_all(cfg: Config, email: str) -> int:
    delivered = 0
    for row in db.pending_for(email):
        try:
            with open(row["path"], "rb") as fh:
                raw = fh.read()
            allowed, dropped = _safe_recipients(cfg, row["recipients"].split(","))
            if dropped:
                _log(syslog.LOG_WARNING,
                     f"Relay-Schutz: fremde Empfaenger in Quarantaene #{row['id']} "
                     f"verworfen: {dropped}")
            if allowed:
                mailer.reinject_raw(cfg, row["email"], allowed, raw)
            db.mark_released(row["id"])
            try:
                os.remove(row["path"])
            except OSError:
                pass
            delivered += 1
        except Exception as e:
            _log(syslog.LOG_ERR,
                 f"Freigabe von Quarantaene-Mail {row['id']} fehlgeschlagen: {e}")
    return delivered


def _send_challenge(cfg: Config, sender: str) -> None:
    if db.challenges_last_hour() >= cfg.max_challenges_per_hour:
        _log(syslog.LOG_WARNING,
             "Challenge-Rate-Limit erreicht -> keine Challenge (Backscatter-Schutz)")
        return
    row = db.get_sender(sender)
    if not row or not row["token"] or not row["captcha_answer"]:
        return
    domain = row["challenge_domain"] or cfg.primary_domain
    try:
        png = captcha.render(row["captcha_answer"], cfg.captcha_width, cfg.captcha_height)
        reply_addr = _reply_address(cfg, row["token"], domain)
        challenge = mailer.build_challenge(cfg, sender, reply_addr,
                                           row["captcha_answer"], png)
        mailer.send(cfg, challenge)
        # Message-ID merken: darueber wird die Antwort spaeter zugeordnet.
        if challenge["Message-ID"]:
            db.set_challenge_msgid(sender, challenge["Message-ID"])
        _log(syslog.LOG_INFO, f"Challenge an {sender} gesendet (Mandant {domain})")
    except Exception as e:
        _log(syslog.LOG_ERR, f"Challenge-Versand an {sender} fehlgeschlagen: {e}")


# ----------------------------------------------------------------- Verify

def _handle_verify(cfg: Config, sender: str, token: str, msg: Message | None) -> int:
    row = _resolve_pending(cfg, token, sender, msg)
    if row is None:
        _log(syslog.LOG_INFO, f"verify: keine offene Challenge zu {sender} gefunden")
        return 0  # verschlucken
    target = row["email"]
    domain = row["challenge_domain"] or cfg.primary_domain

    # Automatisierte Antworten (Vacation-Bots o.ae.) nicht bespielen -> kein Ping-Pong
    if _looks_automated(msg):
        _log(syslog.LOG_INFO, f"verify: automatisierte Antwort fuer {target} ignoriert")
        return 0

    expected = (row["captcha_answer"] or "").upper()
    given = _extract_answer(msg, len(expected)) if expected else None

    if given and given == expected:
        db.allowlist(target)
        delivered = _release_all(cfg, target)
        _log(syslog.LOG_INFO,
             f"verify OK: {target} freigeschaltet (Mandant {domain}), "
             f"{delivered} Mail(s) zugestellt")
        if cfg.send_confirmation:
            try:
                mailer.send(cfg, mailer.build_confirmation(cfg, target, delivered, domain))
            except Exception as e:
                _log(syslog.LOG_ERR, f"Bestaetigung an {target} fehlgeschlagen: {e}")
        return 0

    attempts = db.bump_attempts(target)
    _log(syslog.LOG_INFO,
         f"verify FEHLER fuer {target}: '{given}' (Versuch {attempts}/{cfg.max_attempts})")
    if attempts < cfg.max_attempts and given is not None:
        code = captcha.random_code(cfg.captcha_length)
        newtok = _new_token()
        db.set_waiting(target, newtok, code, domain)   # Tenant-Domain beibehalten
        try:
            png = captcha.render(code, cfg.captcha_width, cfg.captcha_height)
            reply_addr = _reply_address(cfg, newtok, domain)
            retry_msg = mailer.build_challenge(cfg, target, reply_addr, code,
                                               png, retry=True)
            mailer.send(cfg, retry_msg)
            if retry_msg["Message-ID"]:
                db.set_challenge_msgid(target, retry_msg["Message-ID"])
        except Exception as e:
            _log(syslog.LOG_ERR, f"Re-Challenge an {target} fehlgeschlagen: {e}")
    return 0


# ----------------------------------------------------------------- Inbound

def _handle_inbound(cfg: Config, sender: str, recipients, raw: bytes,
                    msg: Message | None) -> int:
    subject = _subject(msg)

    # Null-Sender (Bounces): niemals challengen -> reiner Backscatter-Schutz.
    if _is_null_sender(cfg, sender):
        _log(syslog.LOG_INFO, "Null-Sender still quarantaeniert (kein Challenge)")
        return _quarantine(cfg, sender, recipients, raw, subject)

    row = db.get_sender(sender)
    status = row["status"] if row else "unknown"

    # Harte Blacklist:
    #  - status 'blocked'          -> genau EINMAL Ablehnung senden, dann merken
    #  - status 'blocked_notified' -> jede weitere Mail still verwerfen
    # Kein Ping-Pong: die Ablehnung geht pro gesperrtem Absender nur ein einziges Mal
    # raus (analog zur Challenge), danach Funkstille.
    if status == "blocked_notified":
        _log(syslog.LOG_INFO, f"{sender}: blockiert -> Mail verworfen")
        return 0
    if status == "blocked":
        domain = row["challenge_domain"] or cfg.primary_domain
        if not _is_null_sender(cfg, sender) and not _looks_automated(msg):
            try:
                mailer.send(cfg, mailer.build_rejection(cfg, sender, domain))
                _log(syslog.LOG_INFO, f"{sender}: blockiert -> Ablehnung gesendet (1x)")
            except Exception as e:
                _log(syslog.LOG_ERR, f"Ablehnung an {sender} fehlgeschlagen: {e}")
        else:
            _log(syslog.LOG_INFO, f"{sender}: blockiert (Null-Sender/automatisiert, keine Ablehnung)")
        db.mark_block_notified(sender)      # ab jetzt still verwerfen
        return 0

    # Dynamische Eskalation: verifizierten Absender bei Verdacht zuruckstufen.
    if status == "verified" and cfg.escalation_enabled and _is_suspicious(cfg, msg):
        _log(syslog.LOG_INFO,
             f"Eskalation: {sender} zurueckgestuft (Verdacht auf Bot-Uebernahme)")
        db.reset_sender(sender)
        status = "unknown"

    if status == "verified":
        return _relay(cfg, sender, recipients, raw)

    if status == "waiting":
        # Loop-Protection: still einsammeln, KEINE weitere Auto-Reply.
        return _quarantine(cfg, sender, recipients, raw, subject)

    # ---- unknown: quarantaenen, Status setzen, ggf. Challenge senden ----
    qerr = _quarantine(cfg, sender, recipients, raw, subject)
    if qerr != 0:
        return qerr  # nichts weiter tun; Postfix versucht es erneut

    code = captcha.random_code(cfg.captcha_length)
    token = _new_token()
    domain = _challenge_domain(cfg, recipients)   # Mandant des Empfaengers
    db.set_waiting(sender, token, code, domain)

    if _looks_automated(msg):
        _log(syslog.LOG_INFO,
             f"{sender}: automatisiert erkannt -> quarantaeniert, wartet auf manuellen Bypass")
        return 0

    _send_challenge(cfg, sender)
    return 0


# ------------------------------------------------------------------- main

def main(argv) -> int:
    cfg = load_config()
    syslog.openlog("mailshield")

    if len(argv) < 2:
        _log(syslog.LOG_ERR, "zu wenige Argumente (sender recipient ...)")
        return EX_UNAVAILABLE

    sender = argv[0].strip().lower()
    recipients = [a.strip() for a in argv[1:] if a.strip()]
    raw = sys.stdin.buffer.read()

    try:
        msg = message_from_bytes(raw)
    except Exception:
        msg = None

    db.connect(cfg.db_path)

    # 1) Ist eine CAPTCHA-Antwort dabei?
    for rcpt in recipients:
        token = _match_verify(cfg, rcpt)
        if token is not None:      # "" = feste Adresse verify@, "<tok>" = Subadresse
            return _handle_verify(cfg, sender, token, msg)

    # 2) Normale eingehende Mail an die geschuetzte Domain
    return _handle_inbound(cfg, sender, recipients, raw, msg)
