"""End-to-End-Test der Filterlogik ohne echten Postfix (mailer wird gemockt)."""
import os, tempfile, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tmp = tempfile.mkdtemp()
cfgpath = os.path.join(tmp, "config.yaml")
open(cfgpath, "w").write(f"""
db_path: {tmp}/state.db
quarantine_dir: {tmp}/quar
domains: [hackdv.com, sled-compliance.com]
primary_domain: hackdv.com
domain_labels:
  hackdv.com: "hackdv.com Pruefung"
  sled-compliance.com: "SLED Compliance Pruefung"
send_confirmation: true
escalation_enabled: true
""")
os.environ["MAILSHIELD_CONFIG"] = cfgpath

from shield import mailer, db
from shield.config import load_config
import shield.filter as f

# Mailer mocken -> Ausgaben einsammeln
SENT = []       # (envelope-from, to, EmailMessage)
RELAYED = []    # (sender, recips, raw)
def fake_send(cfg, msg):
    SENT.append((msg["From"], msg["To"], msg))
def fake_reinject(cfg, sender, recips, raw):
    RELAYED.append((sender, list(recips), raw))
mailer.send = fake_send
mailer.reinject_raw = fake_reinject

def run(sender, recipients, raw):
    # frische DB-Connection pro Aufruf (wie separater Postfix-Prozess)
    cfg = load_config()
    db.connect(cfg.db_path)
    for r in recipients:
        tok = f._match_verify(cfg, r)
        if tok:
            from email import message_from_bytes
            return f._handle_verify(cfg, sender.lower(), tok, message_from_bytes(raw))
    from email import message_from_bytes
    return f._handle_inbound(cfg, sender.lower(), recipients, raw, message_from_bytes(raw))

def mail(frm, to, subject, body, extra=""):
    return (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\n{extra}"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").encode()

ok = True
def check(cond, label):
    global ok
    print(("PASS" if cond else "FAIL"), "-", label)
    ok = ok and cond

# 1) Unbekannter Absender -> Quarantaene + Challenge
rc = run("alice@extern.de", ["boss@hackdv.com"],
         mail("alice@extern.de", "boss@hackdv.com", "Hallo", "Bitte anrufen"))
check(rc == 0, "unknown: exit 0")
check(len(SENT) == 1, "unknown: genau 1 Challenge gesendet")
challenge = SENT[0][2]
html = challenge.get_body(preferencelist=("html",)).get_content()
check("cid:" in html, "Challenge: CAPTCHA per CID inline referenziert")
# genau ein Bild-Part, inline (nicht als Attachment):
img_parts = [p for p in challenge.walk() if p.get_content_maintype() == "image"]
check(len(img_parts) == 1, "Challenge: genau ein Inline-Bild")
check(img_parts and img_parts[0].get_content_disposition() == "inline",
      "Challenge: Bild ist inline (kein Attachment)")
# die CID im img-src muss dem Content-ID des Bildes entsprechen
import re as _re
m = _re.search(r'cid:([^"]+)', html)
cid_ref = m.group(1) if m else ""
check(img_parts and img_parts[0]["Content-ID"] == f"<{cid_ref}>",
      "Challenge: img-src cid passt zum Content-ID des Bildes")
reply_addr = challenge["Reply-To"]
check(reply_addr.startswith("verify+") and reply_addr.endswith("@hackdv.com"),
      f"Challenge: Reply-To ist verify+token ({reply_addr})")

# Loesung aus DB holen (das echte CAPTCHA-Bild ist verrauscht)
db.connect(load_config().db_path)
row = db.get_sender("alice@extern.de")
code = row["captcha_answer"]
token = row["token"]
check(row["status"] == "waiting", "unknown: Status -> waiting")

# 2) Zweite Mail waehrend 'waiting' -> still quarantaeniert, KEINE weitere Challenge
SENT.clear()
run("alice@extern.de", ["boss@hackdv.com"],
    mail("alice@extern.de", "boss@hackdv.com", "Nochmal", "Bin noch dran"))
check(len(SENT) == 0, "waiting: keine weitere Auto-Reply (Loop-Protection)")
check(len(db.pending_for("alice@extern.de")) == 2, "waiting: 2 Mails in Quarantaene")

# 3) Falsche Challenge-Antwort -> nicht freigeschaltet, Re-Challenge
SENT.clear(); RELAYED.clear()
run("alice@extern.de", [reply_addr],
    mail("alice@extern.de", reply_addr, "Re: Bestaetigung", "XXXXXX"))
db.connect(load_config().db_path)
check(db.get_sender("alice@extern.de")["status"] == "waiting", "falsch: bleibt waiting")
check(len(RELAYED) == 0, "falsch: nichts zugestellt")
# neuer Token nach Re-Challenge
row = db.get_sender("alice@extern.de"); code = row["captcha_answer"]; token = row["token"]
reply_addr = f"verify+{token}@hackdv.com"

# 4) Richtige Antwort -> Allowlist + alle Quarantaene-Mails zugestellt
SENT.clear(); RELAYED.clear()
run("alice@extern.de", [reply_addr],
    mail("alice@extern.de", reply_addr, "Re: Bestaetigung",
         f"{code}\n\nAm 01.01. schrieb verify: alter Text\n> zitat"))
db.connect(load_config().db_path)
check(db.get_sender("alice@extern.de")["status"] == "verified", "richtig: -> verified")
check(len(RELAYED) == 2, "richtig: beide Quarantaene-Mails zugestellt")
check(len(db.pending_for("alice@extern.de")) == 0, "richtig: Quarantaene geleert")

# 5) Neue Mail eines verifizierten Absenders -> direkt durchgereicht
RELAYED.clear(); SENT.clear()
run("alice@extern.de", ["boss@hackdv.com"],
    mail("alice@extern.de", "boss@hackdv.com", "Follow-up", "Danke!"))
check(len(RELAYED) == 1 and len(SENT) == 0, "verified: direkt an Exchange, keine Challenge")

# 6) Null-Sender (Bounce) -> quarantaeniert, KEINE Challenge (Backscatter-Schutz)
SENT.clear()
run("MAILER-DAEMON", ["boss@hackdv.com"],
    mail("MAILER-DAEMON", "boss@hackdv.com", "Undelivered", "bounce"))
check(len(SENT) == 0, "null-sender: keine Challenge")

# 7) Automatisierte Mail (no-reply) -> quarantaeniert, kein Challenge, wartet auf Bypass
SENT.clear()
run("no-reply@bank.de", ["boss@hackdv.com"],
    mail("no-reply@bank.de", "boss@hackdv.com", "2FA Code", "Ihr Code: 123456"))
check(len(SENT) == 0, "automatisiert: keine Challenge")
check(db.get_sender("no-reply@bank.de")["status"] == "waiting",
      "automatisiert: waiting (manueller Bypass moeglich)")

# 8) Dynamische Eskalation: verifizierter Absender, verdaechtiger Betreff -> Re-Challenge
SENT.clear()
run("alice@extern.de", ["boss@hackdv.com"],
    mail("alice@extern.de", "boss@hackdv.com", "Ticket #4711 auto-reply", "bot text"))
check(len(SENT) == 1, "eskalation: verdaechtige Mail loest neue Challenge aus")

# 9) Relay-Schutz: verifizierter Absender, Fremd-Empfaenger -> NICHT nach aussen
db.connect(load_config().db_path); db.allowlist("carol@extern.de")
RELAYED.clear(); SENT.clear()
run("carol@extern.de", ["opfer@fremd.de"],
    mail("carol@extern.de", "opfer@fremd.de", "Relay?", "leite mich weiter"))
check(len(RELAYED) == 0, "relay-schutz: Fremd-Empfaenger wird NICHT reinjiziert")

# 10) Gemischt: hackdv.com + fremd -> nur hackdv.com wird zugestellt
RELAYED.clear()
run("carol@extern.de", ["boss@hackdv.com", "opfer@fremd.de"],
    mail("carol@extern.de", "boss@hackdv.com, opfer@fremd.de", "Mix", "hi"))
check(len(RELAYED) == 1 and RELAYED[0][1] == ["boss@hackdv.com"],
      "relay-schutz: nur Domain-Empfaenger zugestellt, Fremd verworfen")

# 11) Mandantentrennung: unbekannter Absender an sled-compliance.com
SENT.clear()
run("dave@extern.de", ["kanzlei@sled-compliance.com"],
    mail("dave@extern.de", "kanzlei@sled-compliance.com", "Anfrage", "Bitte um Rueckruf"))
check(len(SENT) == 1, "mandant: Challenge gesendet")
ch = SENT[0][2]
check(ch["Reply-To"].endswith("@sled-compliance.com"),
      f"mandant: Challenge kommt aus sled-compliance.com ({ch['Reply-To']})")
check("SLED Compliance" in ch["From"],
      f"mandant: korrekter Mandanten-Anzeigename ({ch['From']})")
# und Verify laeuft ueber die sled-compliance.com-Adresse
db.connect(load_config().db_path)
r = db.get_sender("dave@extern.de")
check(r["challenge_domain"] == "sled-compliance.com", "mandant: challenge_domain gespeichert")
reply2 = f"verify+{r['token']}@sled-compliance.com"
RELAYED.clear(); SENT.clear()
run("dave@extern.de", [reply2],
    mail("dave@extern.de", reply2, "Re", r["captcha_answer"]))
db.connect(load_config().db_path)
check(db.get_sender("dave@extern.de")["status"] == "verified",
      "mandant: Verify ueber sled-compliance.com erfolgreich")
check(len(RELAYED) == 1, "mandant: Mail an Exchange zugestellt")

# 12) Cross-Tenant sauber getrennt: hackdv.com-Absender bekommt hackdv.com-Challenge
SENT.clear()
run("erik@extern.de", ["info@hackdv.com"],
    mail("erik@extern.de", "info@hackdv.com", "Hi", "text"))
check(SENT[0][2]["Reply-To"].endswith("@hackdv.com"),
      "mandant: hackdv.com-Empfaenger -> hackdv.com-Challenge (keine Vermischung)")

# 13) Spam-Welle: Challenge-Rate-Limit deckelt Backscatter
#     (Postfix-RBL greift schon davor; dies ist die Python-seitige zweite Reihe.)
rl_cfg = os.path.join(tmp, "rl.yaml")
open(rl_cfg, "w").write(f"""
db_path: {tmp}/rl.db
quarantine_dir: {tmp}/rlq
domains: [hackdv.com]
primary_domain: hackdv.com
max_challenges_per_hour: 3
""")
os.environ["MAILSHIELD_CONFIG"] = rl_cfg
SENT.clear()
for i in range(6):
    run(f"spam{i}@extern.de", ["boss@hackdv.com"],
        mail(f"spam{i}@extern.de", "boss@hackdv.com", "Angebot", "billig"))
check(len(SENT) <= 3, f"spam-welle: Challenges auf Limit gedeckelt (<=3), waren {len(SENT)}")
check(len(SENT) < 6, "spam-welle: deutlich weniger Challenges als Absender (Deckel greift)")
db.connect(load_config().db_path)
q = len(db.all_pending())
check(q == 6, f"spam-welle: alle 6 Mails quarantaeniert - kein Verlust (waren {q})")

print()
print("ERGEBNIS:", "ALLE TESTS BESTANDEN" if ok else "FEHLER")
sys.exit(0 if ok else 1)
