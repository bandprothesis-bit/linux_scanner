# DefectDojo server for vulnagent (Docker)

A ready-to-run DefectDojo for the Linux and Windows agents: one folder, one command. It is DefectDojo's own Docker Compose setup, prepared for production:

- **Pinned version:** DefectDojo 3.5.200, with the PostgreSQL 18 and Valkey images that release uses. Upgrades happen when you change `DD_VERSION`.
- **No default passwords:** `setup.sh` writes random secrets to `.env`. Compose refuses to start without them; DefectDojo's own file falls back to secrets that are public.
- **HTTPS out of the box:** a certificate from a local CA that `setup.sh` creates, or your own certificate. Port 8080 redirects to 8443.
- **API user for the agents:** `vulnagent`, with the global role Maintainer (it creates one product per machine), and its API key printed at the end.
- **Images from Docker Hub.** DefectDojo's file pulls through `registry.defectdojo.com`, which logs each pull with your IP address for DefectDojo's sales contact.
- **Ready for production use:** health checks, restart after a reboot, log rotation, and `backup.sh` and `restore.sh`.

## What you need

- A Linux VM: Ubuntu Server 24.04 LTS or Debian 13 is easiest. 4 vCPU, 8 GB RAM, 50 GB disk. A fixed IP address or a DNS name.
- Docker Engine with the Compose plugin. `setup.sh --install-docker` installs both on Ubuntu and Debian 13. On other systems, follow [Docker's install guide](https://docs.docker.com/engine/install/). On Debian 12 too: its `docker-compose` package is the old version 1.
- Internet access to Docker Hub on the first start (about 1.5 GB of images). For a server without internet, see [Server without internet access](#server-without-internet-access).
- Inbound TCP 8443 (HTTPS) from the machines and the browsers, and 8080 if you want the redirect.

## Install

Copy this folder (`defectdojo/server`) to the server, for example to `/opt/defectdojo`, then run:

```bash
cd /opt/defectdojo && sudo ./setup.sh --install-docker --host dojo.example.local
```

`--host` is the name or IP address that the agents and browsers use. `setup.sh` also puts the server's own IP addresses into the certificate, so both the name and the IP work.

It takes 5 to 10 minutes the first time. At the end it prints:

```text
DefectDojo 3.5.200 is running: https://dojo.example.local:8443
  Admin:     admin / <password>   (also in .env; change it after the first login)
  Agent key: <40 characters>   (user vulnagent; print it again with ./setup.sh --agent-token)
  CA:        /opt/defectdojo/ca/defectdojo-ca.crt   (copy it to the agents, see README.md)
```

Log in at that address as `admin`. The browser warns about the certificate until you trust `ca/defectdojo-ca.crt` on your PC: double-click it, *Install Certificate*, *Local Machine*, *Trusted Root Certification Authorities*. Or use your own certificate (see [Your own certificate](#your-own-certificate)).

For a closed lab network without HTTPS, use `sudo ./setup.sh --host 10.0.0.5 --http`, which serves plain HTTP on 8080. The API keys then cross the network in clear text.

Running `setup.sh` again is safe: it keeps `.env` and the certificate, starts whatever isn't running, and prints the summary again.

## Connect the agents

Use the `https://...:8443` address directly. The agents don't follow the redirect from 8080: a redirected upload arrives as an empty request.

**Linux** (see [../README.md](../README.md)):

```bash
sudo DD_API_TOKEN=<agent key> sh defectdojo/install.sh --url https://dojo.example.local:8443
```

```bash
sudo cp defectdojo-ca.crt /etc/vulnagent/defectdojo-ca.crt
```

Then set `"ca_file": "/etc/vulnagent/defectdojo-ca.crt"` in `/etc/vulnagent/defectdojo.json`, before the first upload. The Defender connector uses the same `ca_file` setting in its config.

**Windows** (see [../../windows/README.md](../../windows/README.md)): trust the CA first, in an administrator PowerShell:

```powershell
Import-Certificate -FilePath .\defectdojo-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
$env:DD_API_TOKEN = '<agent key>'; .\install.ps1 -Url https://dojo.example.local:8443
```

For many machines, distribute `defectdojo-ca.crt` with Group Policy (*Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities*), or with an Intune *Trusted certificate* profile.

The CA can sign certificates for any name, so keep `ca/ca.key` on the server only. It never leaves the `ca` folder and isn't mounted into any container.

## Daily operation

Run these in the folder, as root.

| To do this | Run |
|---|---|
| See what runs | `docker compose ps` |
| Logs | `docker compose logs --tail 100 uwsgi` (or `nginx`, `celeryworker`, `initializer`) |
| Stop, start | `docker compose down`, `docker compose up -d` (data is kept in Docker volumes) |
| Restart after changing `.env` | `docker compose up -d` |
| Reset the admin password | `docker compose exec uwsgi ./manage.py changepassword admin` |
| Print the agents' API key again | `./setup.sh --agent-token` |
| Replace the agents' API key | `./setup.sh --new-agent-token` (the old one stops working) |
| New server certificate (it lasts 825 days) | `./setup.sh --renew-cert` |

DefectDojo restarts by itself after a reboot.

## Backups

```bash
sudo ./backup.sh
```

This writes `backups/<date>-<time>/` while DefectDojo keeps running:
- `database.dump`: the PostgreSQL database.
- `media.tar.gz`: uploaded files.
- `config.tar.gz`: `.env` with the secrets, the certificates and the CA.
- `VERSION`: the DefectDojo version.

Backups older than 14 days are deleted (`--keep 30` to change that). `--dir /mnt/backup` writes them somewhere else.

Every night, at 02:00:

```bash
echo '0 2 * * * root /opt/defectdojo/backup.sh >> /var/log/defectdojo-backup.log 2>&1' | sudo tee /etc/cron.d/defectdojo-backup
```

Copy the backups to another machine as well. They contain the secrets, so keep them private.

**Restore**, on the same server or a new one: copy this folder and the backup there, then:

```bash
sudo ./restore.sh backups/20261117-020000
```

It replaces the database and the uploaded files, after you confirm. On a new server without `.env`, it takes `.env`, the certificates and the CA from the backup. That way the secrets match the database, and the agents keep trusting the server, as long as its name stays the same. It runs the DefectDojo version the backup was made with.

## Upgrade

DefectDojo releases often: see [its releases](https://github.com/DefectDojo/django-DefectDojo/releases). To upgrade:

1. Back up: `sudo ./backup.sh`.
2. Set the new version in `.env`, for example `DD_VERSION=3.6.0`.
3. Download and restart:

```bash
sudo docker compose pull && sudo docker compose up -d
```

The `initializer` container applies the database changes before DefectDojo starts. Follow it with `docker compose logs -f initializer`. If a release changes the PostgreSQL or Valkey image in DefectDojo's own `docker-compose.yml`, change it here too. Major PostgreSQL versions need a dump and restore, which is what `backup.sh` and `restore.sh` do.

## Your own certificate

Put the certificate (with its intermediate certificates after it) in `certs/nginx.crt` and the key in `certs/nginx.key`, before the first `setup.sh` or later. Then make both readable by the web container and restart it:

```bash
sudo chown 1001:0 certs/nginx.*
```

```bash
sudo chmod 640 certs/nginx.key && sudo docker compose restart nginx
```

`setup.sh` never overwrites a certificate it didn't create. The certificate must contain the name in `DD_HOSTNAME`.

## Server without internet access

On a machine with internet and Docker, in this folder (with any `.env`, for example one made by `setup.sh` there):

```bash
docker compose pull && docker save $(docker compose config --images) | gzip > defectdojo-images.tar.gz
```

Copy `defectdojo-images.tar.gz` and this folder to the server, then load the images and run setup:

```bash
gunzip -c defectdojo-images.tar.gz | sudo docker load
```

```bash
sudo ./setup.sh --host dojo.example.local --no-pull
```

Install Docker on that server from your own package mirror first; `--install-docker` needs the distribution's package servers.

## Settings (`.env`)

| Setting | Meaning |
|---|---|
| `DD_VERSION` | DefectDojo version (image tag). |
| `DD_IMAGE_REGISTRY` | `docker.io` (Docker Hub), or your own registry mirror. |
| `DD_HOSTNAME`, `DD_SITE_URL` | The server's name and address, used in links that DefectDojo sends. |
| `DD_ALLOWED_HOSTS` | Names and addresses DefectDojo answers to, separated by commas. Add a new name here. |
| `DD_CSRF_TRUSTED_ORIGINS` | The same names as `https://<name>:8443`. Add a new name here as well, or logging in through it fails. |
| `DD_HTTPS`, `DD_SECURE_COOKIES` | `true`/`True` for HTTPS (default); `false`/`False` for plain HTTP on 8080. |
| `DD_BIND_ADDRESS` | `0.0.0.0` listens on every address. Set one address to listen only there, for example `127.0.0.1` behind your own reverse proxy. |
| `DD_PORT`, `DD_TLS_PORT` | Published ports, 8080 and 8443. The redirect from 8080 always points to 8443. |
| `DD_ADMIN_*` | The admin account, created on the first start only. |
| `DD_DATABASE_PASSWORD`, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` | Secrets. Don't change them after the first start: the database password is set once, and the AES key decrypts stored credentials. |

Python settings that have no variable go into `extra_settings/` (see the README there).

## Security notes

- **Docker bypasses the host firewall.** Ports that Docker publishes are not blocked by `ufw` or firewalld rules. To limit who can reach DefectDojo, use the network's firewall, a cloud security group, rules in iptables' `DOCKER-USER` chain, or `DD_BIND_ADDRESS`.
- **Rights of the `vulnagent` user.** It has the global role Maintainer, which can create, change and delete products, findings and engagements. If a machine with the key is lost, replace the key with `./setup.sh --new-agent-token`: the old key stops working at once. Then update the agents with the new one.
- **The admin password** printed by `setup.sh` is also in `.env`. Change it after the first login. The one in `.env` is only used on the very first start.
- **Changing the registry.** `DD_IMAGE_REGISTRY=registry.defectdojo.com` pulls through DefectDojo's registry instead. It avoids Docker Hub's rate limits, but logs your pulls.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `Bad Request (400)` in the browser | The name in the address bar isn't in `DD_ALLOWED_HOSTS`. Add it in `.env`, then `docker compose up -d`. |
| `CSRF verification failed` when logging in | The address isn't in `DD_CSRF_TRUSTED_ORIGINS` (with `https://` and `:8443`). |
| `setup.sh`: `the initializer failed` | Read the log it prints. A full disk or too little memory are the usual causes. |
| `toomanyrequests` while downloading | Docker Hub's rate limit for anonymous downloads. Run `docker login` with a free Docker account, or use a registry mirror. |
| Agents: `certificate verify failed` / `could not establish trust relationship` | The agent doesn't trust `defectdojo-ca.crt` yet (see [Connect the agents](#connect-the-agents)), or the address they use isn't in the certificate. Add the name to `DD_ALLOWED_HOSTS`, then run `./setup.sh --renew-cert`. |
| Agents: `HTTP 405` or an empty upload | They use `http://...:8080`, which redirects. Use `https://...:8443`. |
