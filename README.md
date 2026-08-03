# MailShield

> A stateful challenge–response SMTP gateway that sits in front of Microsoft
> Exchange (or any mailbox server) and forces unknown senders to solve an
> inline image CAPTCHA before their mail is delivered. Keeps support/ticket
> bots out; lets humans through.

MailShield ist ein Challenge-Response-Gateway vor einem Mailserver (z. B.
Microsoft Exchange). Ein vorgelagerter Postfix-MTA nimmt den eingehenden
SMTP-Verkehr an, hält Mail unbekannter Absender in Quarantäne und stellt ein
verrauschtes Bild-CAPTCHA als Auto-Reply. Erst nach korrekter Lösung wird die
geparkte Post an den Mailserver durchgereicht. Ziel: automatisierte
Support-/Inkasso-/Ticket-Bots am Eingang zu einer menschlichen Handlung
zwingen, echte Absender aber ungestört durchlassen.

## Warum

First-Level-Bots haben kein Gedächtnis für den Vorgang, drehen sich im Kreis und
kosten Zeit. MailShield unterbricht das an der richtigen Stelle: Wer etwas will,
löst einmalig ein CAPTCHA – danach ist die Adresse dauerhaft freigeschaltet.

## Architektur

```
Internet :25 -> Postfix smtpd -> content_filter=mailshield -> run_filter.py
                                                                  |
   verifiziert ----------------------------------------> reinject :10026 -> Exchange
   unbekannt   -> Quarantaene + Status "waiting" + CAPTCHA-Mail -> :10026 -> Absender
   wartend     -> Quarantaene (still, keine weitere Auto-Reply)
   verify+<token>@ -> CAPTCHA-Antwort pruefen -> Allowlist + Freigabe -> :10026 -> Exchange
```

Der Bypass-`smtpd` auf `127.0.0.1:10026` reinjiziert **ohne** erneuten Filter
(`-o content_filter=`) und verhindert so Schleifen. Optional signiert OpenDKIM
an dieser Stelle die ausgehenden Challenges (siehe `DKIM-SETUP.md`).

## Features

- **Stateful Challenge-Response** mit drei Zustaenden (unknown / waiting / verified)
- **Inline-CAPTCHA** als CID-Bild direkt im HTML-Body (kein klassischer Anhang)
- **Loop-Protection:** wartende Absender werden still quarantaeniert - keine
  Auto-Reply-Ping-Pong-Schleifen mit anderen Bots
- **Mandantentrennung:** mehrere geschuetzte Domains; die Challenge kommt
  tenant-rein aus der Domain des jeweiligen Empfaengers
- **Open-Relay-Schutz, dreifach** (Postfix `smtpd_relay_restrictions`,
  Loopback-only `mynetworks`, plus App-seitige Empfaenger-Domain-Pruefung)
- **Backscatter-Schutz:** Null-Sender/Bounces und als automatisiert erkannte
  Mail (Bulk, `Auto-Submitted`, `no-reply@...`) bekommen nie eine Challenge;
  zusaetzlich `max_challenges_per_hour` als Deckel
- **Manueller Bypass** fuer legitime Maschinen-Mail (2FA, Passwort-Resets) ueber
  die CLI
- **Dynamische Eskalation:** verifizierte Absender bei Verdacht erneut challengen
- **DKIM-ready:** OpenDKIM-Vorlagen fuer Multi-Domain-Signierung (getrennt vom
  vorhandenen Mailserver-Signer)
- **Wartung** via systemd-Timer (Cleanup alter Quarantaene)
- **CLI-Wrapper** `mailshield` mit Hilfe und Beispielen
- **Selbsttest** deckt die Kernlogik ab (30+ Checks, ohne echten Postfix)

## Zustandsmodell

| Zustand   | Ausloeser                    | Verhalten                                                    |
|-----------|------------------------------|-------------------------------------------------------------|
| unknown   | Absender noch nie gesehen    | Mail -> Quarantaene, CAPTCHA-Challenge als Auto-Reply         |
| waiting   | Challenge laeuft             | weitere Mails **still** in Quarantaene, **keine** weitere Reply |
| verified  | CAPTCHA korrekt geloest      | Allowlist; alle geparkten Mails -> Server, kuenftige direkt durch |

## Voraussetzungen

- Debian 13 (Trixie) oder vergleichbar, Postfix >= 3
- Python 3, `python3-pil` (Pillow), `python3-yaml` (PyYAML), `fonts-dejavu-core`
- Ein nachgelagerter Mailserver (Exchange o. ae.), an den durchgereicht wird

## Schnellstart

```bash
git clone <dein-repo-url> mailshield && cd mailshield
sudo apt-get install -y postfix python3-pil python3-yaml fonts-dejavu-core swaks
sudo ./install.sh
sudoedit /opt/mailshield/config.yaml     # Domains + Ziel-Mailserver anpassen
```

Postfix verdrahten (Snippets aus `postfix/`), Transport zum Mailserver setzen,
`systemctl reload postfix`. Die vollstaendige, schrittweise Anleitung inklusive
Firewall-/NAT-Cutover, TLS und DNS steht in **[DEBIAN13-SETUP.md](DEBIAN13-SETUP.md)**.
DKIM-Signierung der Challenges: **[DKIM-SETUP.md](DKIM-SETUP.md)**.

## Konfiguration (`config.yaml`)

Die wichtigsten Felder (vollstaendig in `config.yaml.example`):

```yaml
domains: [example.com, example.org]   # alle geschuetzten Mandanten-Domains
primary_domain: example.com           # Fallback fuer die Verify-Adresse
reinject_host: 127.0.0.1              # Bypass-smtpd (siehe master.cf)
reinject_port: 10026
captcha_length: 6
max_challenges_per_hour: 200          # Backscatter-Deckel
retention_days: 30                    # Aufbewahrung fuer 'cleanup'
escalation_enabled: false             # Re-Challenge bei Verdacht
```

## CLI

```bash
mailshield                      # Hilfe mit Beispielen
mailshield list                 # Quarantaene
mailshield senders              # Absender + Status
mailshield show alice@extern.de # Details
mailshield release no-reply@bank.de   # manueller Bypass (2FA/Reset freigeben)
mailshield reset alice@extern.de      # neue Challenge erzwingen
mailshield cleanup --days 30          # alte Quarantaene aufraeumen
```

## Sicherheit

**Open-Relay-Schutz** ist bewusst dreifach ausgelegt: Postfix
`smtpd_relay_restrictions`, ein absichtlich auf Loopback beschraenktes
`mynetworks`, und - als App-seitige Absicherung - reinjiziert der Filter nur
Empfaenger der konfigurierten Domains. Selbst bei einer Postfix-Fehlkonfiguration
verlaesst so keine Fremd-Domain-Mail das System.

**Backscatter:** Challenge-Response verschickt Auto-Replies an den
Envelope-Sender. Bei gefaelschtem Spam traefe das Unbeteiligte. Deshalb werden
Null-Sender/Bounces und automatisierte Mail nie gechallenget, es gilt ein
Stunden-Limit, und MailShield gehoert **hinter** eine regulaere Spam-/RBL-Pruefung.

## Tests

```bash
python3 selftest.py   # End-to-End-Logik ohne echten Postfix (Mailversand gemockt)
```

## Projektstruktur

```
shield/            Applikationscode (config, db, captcha, mailer, filter, cli)
run_filter.py      Postfix-pipe-Einstiegspunkt (pro Mail aufgerufen)
run_cli.py         Admin-CLI-Einstiegspunkt
bin/mailshield     CLI-Wrapper fuer /usr/local/bin
postfix/           main.cf-/master.cf-Snippets + transport-Beispiel
dkim/              OpenDKIM-Vorlagen (Multi-Domain-Signierung)
systemd/           Maintenance-Timer + tmpfiles
config.yaml.example  Beispiel-Konfiguration
install.sh         Installation nach /opt/mailshield
DEBIAN13-SETUP.md  vollstaendige Einrichtung (Firewall, TLS, DNS, Cutover)
DKIM-SETUP.md      DKIM-Signierung der Challenges
selftest.py        Selbsttest der Kernlogik
```

## Hinweis zu Beispielwerten

Die Setup-Anleitungen und Postfix-/DKIM-Vorlagen enthalten konkrete Beispiel-
Werte aus einer realen Installation (Domains, interne IPs, Selektoren).
**Ersetze Domains, IP-Adressen und DKIM-Selektoren durch deine eigenen.**

## Wie der Filter laeuft (kein Daemon)

`run_filter.py` ist **kein** Dienst - Postfix startet es ueber den
`mailshield`-Pipe-Service pro Mail selbst. Es gibt also keinen langlaufenden
Prozess ausser Postfix und (optional) OpenDKIM. Der einzige systemd-Timer dient
dem taeglichen Cleanup.

## Lizenz

MIT - siehe [LICENSE](LICENSE).

---

*MailShield ist ein defensives Anti-Bot-Gateway fuer den eigenen Mailserver.
Bedenke bei zeitkritischer Post (z. B. Fristen im Mahn-/Inkassowesen), dass
quarantaenierte Mail auf die manuelle Freigabe wartet - ein regelmaessiger Blick
in `mailshield list` gehoert dazu.*
# MailShield
# MailShield
