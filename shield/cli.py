"""Admin-Kommandozeile fuer MailShield (manueller Bypass, Statusverwaltung)."""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime

from . import captcha, db, mailer
from .config import load_config


def _ts(v):
    if not v:
        return "-"
    return datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M")


def cmd_init(cfg, args):
    db.connect(cfg.db_path)
    os.makedirs(cfg.quarantine_dir, exist_ok=True)
    print(f"DB:          {cfg.db_path}")
    print(f"Quarantaene: {cfg.quarantine_dir}")
    print("Initialisiert.")


def cmd_list(cfg, args):
    db.connect(cfg.db_path)
    rows = db.all_pending()
    if not rows:
        print("Quarantaene ist leer.")
        return
    print(f"{'ID':>5}  {'Empfangen':16}  {'Absender':32}  Betreff")
    print("-" * 90)
    for r in rows:
        print(f"{r['id']:>5}  {_ts(r['received_at']):16}  "
              f"{r['email'][:32]:32}  {(r['subject'] or '')[:28]}")


def cmd_senders(cfg, args):
    db.connect(cfg.db_path)
    rows = db.list_senders()
    if not rows:
        print("Keine bekannten Absender.")
        return
    print(f"{'Status':9}  {'Absender':40}  {'Versuche':>8}  Aktualisiert")
    print("-" * 84)
    for r in rows:
        print(f"{r['status']:9}  {r['email'][:40]:40}  {r['attempts']:>8}  "
              f"{_ts(r['updated_at'])}")


def _release(cfg, email):
    delivered = 0
    domains = [d.lower() for d in cfg.domains]

    def _safe(recips):
        return [r for r in recips
                if "@" in r and r.rsplit("@", 1)[1].strip().lower() in domains]

    for row in db.pending_for(email):
        try:
            with open(row["path"], "rb") as fh:
                raw = fh.read()
            allowed = _safe(row["recipients"].split(","))
            if allowed:
                mailer.reinject_raw(cfg, row["email"], allowed, raw)
            db.mark_released(row["id"])
            try:
                os.remove(row["path"])
            except OSError:
                pass
            delivered += 1
        except Exception as e:
            print(f"  ! Freigabe von #{row['id']} fehlgeschlagen: {e}", file=sys.stderr)
    return delivered


def cmd_release(cfg, args):
    """Manueller Bypass: Absender auf Allowlist + alle Mails zustellen."""
    db.connect(cfg.db_path)
    email = args.email.lower()
    db.allowlist(email)
    n = _release(cfg, email)
    print(f"{email}: auf Allowlist gesetzt, {n} Mail(s) zugestellt.")


def cmd_allow(cfg, args):
    """Nur auf Allowlist setzen (ohne Quarantaene freizugeben)."""
    db.connect(cfg.db_path)
    db.allowlist(args.email.lower())
    print(f"{args.email.lower()}: auf Allowlist gesetzt.")


def cmd_reset(cfg, args):
    """Zuruecksetzen -> naechste Mail loest neue Challenge aus (Eskalation)."""
    db.connect(cfg.db_path)
    db.reset_sender(args.email.lower())
    print(f"{args.email.lower()}: zurueckgesetzt (unknown).")


def cmd_show(cfg, args):
    db.connect(cfg.db_path)
    email = args.email.lower()
    row = db.get_sender(email)
    print(f"Absender: {email}")
    if row:
        print(f"  Status:      {row['status']}")
        print(f"  Versuche:    {row['attempts']}")
        print(f"  Angelegt:    {_ts(row['created_at'])}")
        print(f"  Aktualisiert:{_ts(row['updated_at'])}")
    else:
        print("  Status:      unknown (kein Datensatz)")
    pending = db.pending_for(email)
    print(f"  Quarantaene: {len(pending)} Mail(s)")
    for p in pending:
        print(f"    #{p['id']}  {_ts(p['received_at'])}  {(p['subject'] or '')[:50]}")


def cmd_gen_captcha(cfg, args):
    code = captcha.random_code(cfg.captcha_length)
    png = captcha.render(code, cfg.captcha_width, cfg.captcha_height)
    out = args.out or "captcha.png"
    with open(out, "wb") as fh:
        fh.write(png)
    print(f"Code: {code}  ->  {out} ({len(png)} Bytes)")


def cmd_cleanup(cfg, args):
    """Alte Quarantaene-Mails und verwaiste 'waiting'-Absender entfernen."""
    db.connect(cfg.db_path)
    days = args.days if args.days is not None else cfg.retention_days
    cutoff = time.time() - days * 86400

    q_removed = 0
    for row in db.expired_quarantine(cutoff):
        try:
            os.remove(row["path"])
        except OSError:
            pass
        db.delete_quarantine(row["id"])
        q_removed += 1

    s_removed = 0
    for s in db.stale_waiting(cutoff):
        if not db.pending_for(s["email"]):      # nur wenn nichts mehr geparkt ist
            db.reset_sender(s["email"])
            s_removed += 1

    print(f"Cleanup (>{days} Tage): {q_removed} Quarantaene-Mail(s) entfernt, "
          f"{s_removed} verwaiste 'waiting'-Absender zurueckgesetzt.")


_EXAMPLES = """\
Beispiele:
  mailshield list                       Quarantaene anzeigen
  mailshield senders                    alle Absender + Status
  mailshield show alice@extern.de       Details zu einem Absender
  mailshield release no-reply@bank.de   manueller Bypass (2FA/Reset freigeben)
  mailshield allow chef@partner.de      nur auf Allowlist setzen
  mailshield reset alice@extern.de      neue Challenge erzwingen
  mailshield cleanup --days 30          alte Quarantaene aufraeumen
  mailshield gen-captcha -o test.png    Test-CAPTCHA erzeugen

Ohne Argumente zeigt 'mailshield' diese Hilfe. Zu jedem Befehl gibt es
Detailhilfe, z. B.:  mailshield release -h
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="mailshield",
        description="MailShield Admin-CLI - Verwaltung von Quarantaene und Allowlist.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-c", "--config", help="Pfad zur config.yaml")
    sub = p.add_subparsers(dest="cmd", metavar="BEFEHL")

    sub.add_parser("init", help="DB/Verzeichnisse anlegen").set_defaults(fn=cmd_init)
    sub.add_parser("list", help="Quarantaene auflisten").set_defaults(fn=cmd_list)
    sub.add_parser("senders", help="Bekannte Absender + Status").set_defaults(fn=cmd_senders)

    for name, fn, hlp in [
        ("release", cmd_release, "Manueller Bypass: freischalten + zustellen"),
        ("allow", cmd_allow, "Nur auf Allowlist setzen"),
        ("reset", cmd_reset, "Zuruecksetzen (neue Challenge erzwingen)"),
        ("show", cmd_show, "Details zu einem Absender"),
    ]:
        sp = sub.add_parser(name, help=hlp)
        sp.add_argument("email")
        sp.set_defaults(fn=fn)

    gc = sub.add_parser("gen-captcha", help="Test-CAPTCHA erzeugen")
    gc.add_argument("-o", "--out", help="Ausgabedatei (Default captcha.png)")
    gc.set_defaults(fn=cmd_gen_captcha)

    cl = sub.add_parser("cleanup", help="Alte Quarantaene/Absender aufraeumen")
    cl.add_argument("--days", type=int, default=None,
                    help="Aufbewahrung in Tagen (Default: retention_days aus config)")
    cl.set_defaults(fn=cmd_cleanup)
    return p


def main(argv=None):
    parser = build_parser()
    args_list = sys.argv[1:] if argv is None else list(argv)
    if not args_list:                 # ohne Argumente: Hilfe zeigen statt Fehler
        parser.print_help()
        return 0
    args = parser.parse_args(args_list)
    cfg = load_config(args.config)
    return args.fn(cfg, args)
