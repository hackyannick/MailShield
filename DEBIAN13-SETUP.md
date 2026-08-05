# MailShield auf Debian 13 (Trixie) – Einrichtung

Umgebung dieser Anleitung:

```
Internet ──► FTDv ──(NAT :25)──► MTA mail.hackdv.com 10.0.201.5 ──(smtp)──► Exchange 10.0.201.6
```

MTA und Exchange liegen hier im selben Segment (10.0.201.0/24); der Hop
MTA→Exchange berührt die FTDv nicht. IPs bei Bedarf anpassen.

---

## 1. Pakete installieren

```bash
sudo apt-get update
sudo apt-get install -y \
    postfix \
    python3 \
    python3-pil \
    python3-yaml \
    fonts-dejavu-core \
    swaks \
    ca-certificates
```

Zweck der Pakete:

| Paket             | Wofür                                                        |
|-------------------|-------------------------------------------------------------|
| `postfix`         | der MTA selbst                                               |
| `python3`         | Laufzeit für Filter + CLI (in Debian 13 vorhanden)          |
| `python3-pil`     | Pillow – CAPTCHA-Bilderzeugung (apt statt pip wegen PEP 668) |
| `python3-yaml`    | PyYAML – Konfigurationsdatei                                 |
| `fonts-dejavu-core` | Schrift für das CAPTCHA (`DejaVuSans-Bold.ttf`)           |
| `swaks`           | SMTP-Testtool für den Cutover                               |
| `ca-certificates` | für ausgehendes STARTTLS                                     |

Bei der Postfix-Installation fragt debconf:
- **General type:** `Internet Site`
- **System mail name:** `mail.hackdv.com`

(Beides lässt sich später mit `sudo dpkg-reconfigure postfix` ändern.)

Optional für ein TLS-Zertifikat auf `mail.hackdv.com`:

```bash
sudo apt-get install -y certbot
```

---

## 2. MailShield installieren

Projekt auf den Server bringen (z. B. `scp mailshield.zip`), dann:

```bash
unzip mailshield.zip && cd mailshield
sudo ./install.sh
```

Das Skript legt den Systembenutzer `mailshield`, `/opt/mailshield`,
`/var/lib/mailshield/{,quarantine}` an und initialisiert die Datenbank.

Danach die Konfiguration prüfen (Domain/Exchange stehen dort schon richtig,
falls du diese Anleitung 1:1 nutzt):

```bash
sudo nano /opt/mailshield/config.yaml
```

---

## 3. Postfix verdrahten

Die Snippets aus `postfix/` in die echten Dateien übernehmen:

```bash
# main.cf – Inhalt von postfix/main.cf.snippet anhängen/einfügen
sudo tee -a /etc/postfix/main.cf < postfix/main.cf.snippet

# master.cf – Inhalt von postfix/master.cf.snippet anhängen
sudo tee -a /etc/postfix/master.cf < postfix/master.cf.snippet

# transport zur Exchange-IP
sudo cp postfix/transport /etc/postfix/transport
sudo postmap /etc/postfix/transport
```

> Prüfe `main.cf` danach auf **doppelte** Parameter (falls Defaults schon gesetzt
> waren). Bei Konflikten gilt der letzte Eintrag – die Snippet-Werte sollen gewinnen.

TLS-Zertifikat ablegen (Pfade wie im Snippet):

```bash
sudo mkdir -p /etc/ssl/mail.hackdv.com
# fullchain.pem + privkey.pem dorthin kopieren (z. B. aus certbot/deiner internen CA)
sudo chmod 600 /etc/ssl/mail.hackdv.com/privkey.pem
```

Konfiguration testen und laden:

```bash
sudo postfix check          # meldet Syntaxfehler
sudo systemctl restart postfix
```

---

## 4. FTDv anpassen

- Bestehende Inbound-NAT `outside :25 → 10.0.201.6` **umbiegen** auf
  `→ 10.0.201.5` (MTA). ACP-Regel `outside → MTA tcp/25` entsprechend.
- MTA **ausgehend** erlauben: `10.0.201.5 → outside tcp/25` (Challenges/Confirms)
  und `10.0.201.5 → outside udp/53` (DNS/MX-Lookups).
- **SMTP/ESMTP-Inspection** der FTDv für diesen Pfad prüfen/deaktivieren –
  sie kann STARTTLS/Pipelining stören, sobald ein eigener MTA davor steht.

---

## 5. Cutover-Test (erst testen, dann NAT umlegen)

Noch mit **alter** NAT, lokal auf dem MTA:

```bash
# a) Nimmt Exchange von uns an?
swaks --to postmaster@hackdv.com --server 10.0.201.6:25

# b) Reinjection-Weg (wie MailShield zustellt) -> landet es im Exchange?
swaks --to postmaster@hackdv.com --server 127.0.0.1:10026

# c) Ausgehend über die FTDv (Challenge-Weg) -> kommt es an?
swaks --to postmaster@hackdv.com --from verify@hackdv.com
```

Erst wenn a–c sauber sind, die **Inbound-NAT :25 auf 10.0.201.5** umlegen und
beobachten:

```bash
sudo tail -f /var/log/mail.log
python3 /opt/mailshield/run_cli.py list       # Quarantäne
python3 /opt/mailshield/run_cli.py senders     # Status je Absender
```

Rollback ist trivial: NAT-Ziel zurück auf `10.0.201.6`.

---

## 6. Open-Relay-Gegenprobe (wichtig)

Von einem **externen** Host testen, dass Relay verweigert wird:

```bash
swaks --to fremde-adresse@example.org \
      --from angreifer@irgendwo.tld \
      --server <oeffentliche-IP> --port 25
```

Erwartet: `554 5.7.1 <…>: Relay access denied`. Empfänger `@hackdv.com` werden
akzeptiert (und dann von MailShield behandelt), alles andere wird abgewiesen.

Zusätzliche Absicherung greift **im Filter selbst**: MailShield reinjiziert
grundsätzlich nur Empfänger der konfigurierten `domains`. Selbst wenn Postfix
(durch Fehlkonfiguration) eine Fremd-Adresse durchließe, würde MailShield sie
nicht nach außen weiterreichen, sondern verwerfen und im Log vermerken.

---

## 7. DNS / Deliverability (für BEIDE Mandanten)

Challenge-Mails gehen tenant-rein aus der jeweiligen Empfängerdomain raus
(`verify+…@hackdv.com` bzw. `verify+…@sled-compliance.com`), ausgehend vom MTA.
Deshalb pro Domain:

- **MX** bleibt jeweils auf der öffentlichen IP.
- **SPF** von **beiden** Domains (`hackdv.com` **und** `sled-compliance.com`) muss
  die Ausgangs-IP des MTA einschließen — sonst schlägt SPF bei den Challenges fehl.
- **PTR** der Ausgangs-IP → `mail.hackdv.com` (ein PTR pro IP; das ist ok, SPF/DKIM
  tragen die Domain-Zuordnung).
- **TLS:** Der MTA präsentiert **ein** Zertifikat. Verwende ein **SAN-Zertifikat**,
  das die MX-Hostnamen beider Domains abdeckt (z. B. `mail.hackdv.com` +
  `mail.sled-compliance.com`). Alternativ tolerieren die meisten Sender opportunistisches
  TLS (`may`) auch bei Namensabweichung — sauber ist der SAN-Cert.
- **DKIM** signiert der Exchange je Mandant; reine Challenge-Mails wären unsigniert.
  Bei Problemen `opendkim` auf dem MTA nachrüsten und beide Domains dort einrichten
  (`apt-get install opendkim opendkim-tools`).

Mandantentrennung im Exchange bleibt unberührt: MailShield reicht die Post 1:1 an
`10.0.201.6` weiter; welche Accepted Domain / Address Book Policy greift, entscheidet
der Exchange. MailShield sorgt lediglich dafür, dass **Challenges den Mandanten nicht
vermischen** (ein `sled-compliance.com`-Absender bekommt nie eine `hackdv.com`-Antwort).

---

## 8. Kein Daemon nötig – aber ein Wartungs-Timer

**Wichtig:** `run_filter.py` ist **kein** Dienst. Postfix startet es über den
`mailshield`-Pipe-Service (`master.cf`) **pro Mail** selbst. Ein systemd-Service,
der es „am Laufen hält", wäre falsch. Kontrolle:

```bash
postconf -M mailshield        # zeigt den pipe-Service
swaks --to postmaster@hackdv.com --server 127.0.0.1:10026   # Rauchtest
```

Sinnvoll ist dagegen ein **täglicher Cleanup** (alte Quarantäne + verwaiste
`waiting`-Absender). `install.sh` richtet das automatisch ein; manuell:

```bash
sudo cp systemd/mailshield.tmpfiles.conf /etc/tmpfiles.d/mailshield.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mailshield.conf
sudo cp systemd/mailshield-maintenance.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mailshield-maintenance.timer
```

Prüfen / manuell auslösen:

```bash
systemctl status mailshield-maintenance.timer
systemctl start  mailshield-maintenance.service      # sofort laufen lassen
journalctl -u mailshield-maintenance.service         # Ergebnis
```

Aufbewahrung steuert `retention_days` in `config.yaml` (Default 30). Einmalig
testen ohne zu warten: `python3 /opt/mailshield/run_cli.py cleanup --days 30`.

---

## Cheatsheet
```bash
python3 /opt/mailshield/run_cli.py list
python3 /opt/mailshield/run_cli.py senders
python3 /opt/mailshield/run_cli.py show alice@extern.de
python3 /opt/mailshield/run_cli.py release no-reply@bank.de   # 2FA/Reset freigeben
python3 /opt/mailshield/run_cli.py reset  alice@extern.de     # neue Challenge erzwingen
sudo tail -f /var/log/mail.log
```
