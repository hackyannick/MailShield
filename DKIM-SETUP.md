# DKIM für MailShield-Challenges (OpenDKIM)

Selectors deiner Mandanten: Exchange nutzt hkdv (hackdv.com) bzw. ds
(sled-compliance.com). Der MTA-Shield nutzt den getrennten Selector "shield",
damit sich nichts ueberschneidet.

Ziel: Die ausgehenden Challenge-/Bestätigungs-Mails (`verify@…`) DKIM-signieren,
damit Gmail/o365 sie nicht als Spam einstufen. Durchgereichte Fremd-Mail bleibt
**unsigniert** (nur unsere Mandanten-Domains werden signiert).

## Architektur-Feinheit (wichtig!)

Die Challenges werden lokal über `127.0.0.1 → :10026` (Bypass-smtpd) eingeliefert.
Damit OpenDKIM sie signiert, muss der **Milter auf dem :10026-smtpd** laufen — und
dort ist er per `no_milters` aktuell **deaktiviert**. Das wird unten geändert.
OpenDKIM signiert nur Mail, deren From in der `signing.table` steht — die
durchgereichte Fremd-Mail (anderer From) bleibt also unangetastet.

## 1. Installieren

```bash
apt-get install -y opendkim opendkim-tools
mkdir -p /etc/dkimkeys
```

## 2. Schlüssel je Mandant erzeugen (Selector: shield)

```bash
cd /etc/dkimkeys
opendkim-genkey -b 2048 -d hackdv.com          -s shield -D /etc/dkimkeys
mv shield.private hackdv.com.private ; mv shield.txt hackdv.com.txt
opendkim-genkey -b 2048 -d sled-compliance.com -s shield -D /etc/dkimkeys
mv shield.private sled-compliance.com.private ; mv shield.txt sled-compliance.com.txt

chown -R opendkim:opendkim /etc/dkimkeys
chmod 600 /etc/dkimkeys/*.private
```

## 3. Konfiguration ablegen

```bash
cp dkim/opendkim.conf  /etc/opendkim.conf
cp dkim/signing.table  /etc/dkimkeys/signing.table
cp dkim/key.table      /etc/dkimkeys/key.table
cp dkim/trusted.hosts  /etc/dkimkeys/trusted.hosts
chown -R opendkim:opendkim /etc/dkimkeys

systemctl enable --now opendkim
systemctl status opendkim --no-pager
ss -ltnp | grep 8891        # OpenDKIM lauscht auf localhost:8891
```

## 4. Postfix mit OpenDKIM verbinden

Global in `main.cf` (nur Defaults, schadet nichts):

```bash
postconf -e 'milter_default_action = accept'    # OpenDKIM aus -> Mail laeuft trotzdem
postconf -e 'milter_protocol = 6'
```

**Den Milter am :10026-smtpd aktivieren** — in `master.cf` beim
`127.0.0.1:10026`-Stanza:

- die Option `no_milters` aus `receive_override_options` **entfernen**,
- eine Zeile `-o smtpd_milters=inet:localhost:8891` **ergänzen**.

Das Stanza sieht danach so aus:

```
127.0.0.1:10026 inet n  -       n       -       10      smtpd
  -o content_filter=
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
  -o smtpd_milters=inet:localhost:8891
  -o smtpd_helo_restrictions=
  -o smtpd_client_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o mynetworks=127.0.0.0/8,[::1]/128
  -o smtpd_authorized_xforward_hosts=127.0.0.0/8,[::1]/128
```

Danach:

```bash
postfix check && systemctl restart postfix
```

## 5. DNS – die DKIM-TXT-Records veröffentlichen

Der Inhalt steht in den `.txt`-Dateien aus Schritt 2:

```bash
cat /etc/dkimkeys/hackdv.com.txt
cat /etc/dkimkeys/sled-compliance.com.txt
```

Jeweils einen TXT-Record anlegen:

```
shield._domainkey.hackdv.com            IN TXT  "v=DKIM1; k=rsa; p=<PUBKEY>"
shield._domainkey.sled-compliance.com   IN TXT  "v=DKIM1; k=rsa; p=<PUBKEY>"
```

(Die `.txt`-Datei liefert den fertigen Record inkl. Klammern/Anführungszeichen.
Bei langen 2048-Bit-Keys ggf. auf mehrere Strings aufgeteilt — die meisten
DNS-Provider nehmen den Inhalt so.)

## 6. Testen

```bash
# a) signiert OpenDKIM lokal?
opendkim-testkey -d hackdv.com -s shield -vvv           # "key OK" erwartet
opendkim-testkey -d sled-compliance.com -s shield -vvv

# b) echte Challenge ausloesen und im Ziel-Header pruefen:
mailshield reset hack.yannick@gmail.com
# vom Handy an yannick.hack@hackdv.com; dann in Gmail "Original anzeigen":
#   dkim=pass header.d=hackdv.com   <- Ziel
#   dmarc=pass
```

## Erwartetes Ergebnis

Vorher: `spf=pass; dmarc=pass` (DKIM fehlt).
Nachher: `spf=pass; dkim=pass header.d=hackdv.com; dmarc=pass` — DMARC besteht dann
über **beide** Mechanismen. Zusammen mit einem PTR auf der Sende-IP ist das der
stärkste Hebel gegen die Spam-Einstufung.
