#!/usr/bin/env bash
# Einfache Installation nach /opt/mailshield. Als root ausfuehren.
set -euo pipefail

DEST=/opt/mailshield
STATE=/var/lib/mailshield

echo ">> Benutzer 'mailshield' anlegen (falls noetig)"
id -u mailshield >/dev/null 2>&1 || useradd --system --home "$STATE" --shell /usr/sbin/nologin mailshield

echo ">> Dateien nach $DEST kopieren"
mkdir -p "$DEST"
cp -r shield run_filter.py run_cli.py requirements.txt config.yaml.example "$DEST/"

echo ">> Zustandsverzeichnisse"
mkdir -p "$STATE/quarantine"
chown -R mailshield:mailshield "$STATE"

echo ">> Python-Abhaengigkeiten pruefen"
if python3 -c "import PIL, yaml" 2>/dev/null; then
  echo "   Pillow + PyYAML bereits vorhanden (apt-Pakete)."
else
  echo "   Fehlend. Unter Debian/Ubuntu bitte per apt installieren:"
  echo "     apt-get install -y python3-pil python3-yaml fonts-dejavu-core"
  echo "   (oder als Fallback: pip3 install --break-system-packages -r $DEST/requirements.txt)"
  exit 1
fi

if [ ! -f "$DEST/config.yaml" ]; then
  cp "$DEST/config.yaml.example" "$DEST/config.yaml"
  echo ">> $DEST/config.yaml angelegt – bitte anpassen (Domain, Exchange-Host)."
fi

echo ">> DB initialisieren"
sudo -u mailshield python3 "$DEST/run_cli.py" init

echo ">> CLI-Wrapper nach /usr/local/bin/mailshield"
if [ -f bin/mailshield ]; then
  install -m 0755 bin/mailshield /usr/local/bin/mailshield
  echo "   -> 'mailshield' ist jetzt systemweit aufrufbar."
fi

echo ">> systemd-tmpfiles + Maintenance-Timer"
if [ -d systemd ]; then
  cp systemd/mailshield.tmpfiles.conf /etc/tmpfiles.d/mailshield.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/mailshield.conf || true
  cp systemd/mailshield-maintenance.service /etc/systemd/system/
  cp systemd/mailshield-maintenance.timer   /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now mailshield-maintenance.timer
fi

cat <<'MSG'

Fertig. Naechste Schritte:
  1) $DEST/config.yaml anpassen (domains, primary_domain, Exchange-Transport).
  2) postfix/main.cf.snippet und postfix/master.cf.snippet in Postfix uebernehmen.
  3) /etc/postfix/transport pflegen + 'postmap /etc/postfix/transport'.
  4) 'systemctl reload postfix'.

Hinweis: Der Filter laeuft NICHT als Daemon - Postfix startet run_filter.py pro
Mail selbst (pipe-Service 'mailshield'). Der systemd-Timer macht nur den taeglichen
Cleanup.

Admin:  python3 /opt/mailshield/run_cli.py list
Timer:  systemctl status mailshield-maintenance.timer
MSG
