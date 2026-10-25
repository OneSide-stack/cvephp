# PHP2Shell Lab — Vulnerable Corporate Web App VM

A self-contained, **deliberately vulnerable** Docker environment that replicates a
realistic corporate SaaS deployment ("Nimbus Analytics", an enterprise analytics
dashboard) for analysing and testing the **PHP2Shell** vulnerabilities:

| CVE | Class | CVSS v4.0 | Fixed in |
| --- | --- | --- | --- |
| CVE-2026-109618 | RCE via out-of-memory corruption (`longjmp` leaves request memory uninitialized) | 9.2 | PHP 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35 |
| CVE-2026-109619 | RCE via stale global state (freed request memory reused by later requests on the same worker) | 9.2 | PHP 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35 |

Both flaws live in the **PHP engine itself** (not in application code), affect the
**PHP-FPM SAPI**, and are pre-auth — so the target here is the runtime:

* **Base image:** `php:8.4.26-fpm-alpine` — the last 8.4 release *before* the
  PHP2Shell patches.
* **Topology:** all-in-one "VM-style" container — `supervisord` (PID 1) runs
  **nginx** (port 80) and **PHP-FPM** (127.0.0.1:9000) together.
* **App:** a single functional `index.php` in `/var/www/html` containing the
  entire UI — Tailwind (compiled & embedded), charts, dark/light mode, live
  telemetry API. No CDN or external assets; works fully air-gapped.

> ⚠️ **Safety:** this image ships a known-vulnerable, internet-exploited PHP
> runtime. Run it only on an isolated machine/network you control. Never expose
> it publicly.

---

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds the all-in-one lab VM (`ARG PHP_IMAGE` defaults to `php:8.4.26-fpm-alpine`) |
| `nginx.conf` | Complete standalone nginx config — front door on `:80`, proxies `\.php$` to the PHP-FPM backend on port `9000` |
| `supervisord.conf` | Process manager: php-fpm (priority 5) + nginx (priority 10), logs to container stdout/stderr |
| `php2shell.ini` | Explicit PHP runtime posture (errors on, generous limits, UTC) |
| `index.php` | The complete Nimbus Analytics dashboard UI + JSON API, single file |
| `.dockerignore` | Keeps the build context minimal |

## Architecture

```
                    ┌────────────────── one container: php2shell-vm ──────────────────┐
                    │                                                                  │
  host :80 ────────►│  nginx :80 (supervised)                                          │
                    │    ├── static /  → /var/www/html                                 │
                    │    ├── \.php$  ── FastCGI ──► php-fpm 127.0.0.1:9000 (supervised)│
                    │    │                             └─ PHP 8.4.26 (CVE-2026-109618/-619)
                    │    └── /healthz (nginx-served liveness)                          │
                    │  supervisord = PID 1  (docker logs -f php2shell-vm)              │
                    └──────────────────────────────────────────────────────────────────┘
```

## Build & run

```bash
cd php2shell-lab

# 1. build the image
docker build -t php2shell-lab:8.4.26 .

# 2. run the "VM" — port 80 exposed to the host
docker run -d --name php2shell-vm -p 80:80 php2shell-lab:8.4.26

# 3. open the app
open http://localhost/        # macOS
xdg-open http://localhost/    # Linux
```

Port 80 already taken? Publish it elsewhere:

```bash
docker run -d --name php2shell-vm -p 8080:80 php2shell-lab:8.4.26
```

## Verify the environment

```bash
# full-stack healthcheck (nginx → FastCGI → PHP-FPM → engine)
curl -s http://localhost/index.php?api=ping
# → {"status":"ok","service":"nimbus-analytics","php":"8.4.26","sapi":"fpm-fcgi", ...}

# the System Health badge in the UI header is injected live from PHP_VERSION
curl -s http://localhost/ | grep -oE 'PHP&nbsp;[0-9.]+'
# → PHP&nbsp;8.4.26

# confirm the runtime from inside the container
docker exec php2shell-vm php -v
# → PHP 8.4.26 (cli) ...   (the FPM workers run the same engine build)

# both daemons are supervised
docker exec php2shell-vm supervisorctl status
# → nginx      RUNNING
#   php-fpm    RUNNING

# unified VM logs (supervisord + nginx + php-fpm stderr)
docker logs -f php2shell-vm
```

In the browser, the header badge reads **`System Health: Operational · PHP 8.4.26`**
(green pulsing dot), and *Runtime Environment* in the sidebar shows the live
SAPI, Zend version, ini posture, loaded extensions, and container uptime —
use it to confirm exactly which build you're testing before each run.

## Working with the lab

```bash
# an interactive shell on the "VM"
docker exec -it php2shell-vm sh

# run the app with extra debugging affordances (strace/gdb-friendly)
docker run -d --name php2shell-vm-debug \
  -p 80:80 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  php2shell-lab:8.4.26

# keep exploit payloads/mounters outside the image
docker cp ./payload.php php2shell-vm:/tmp/
docker run -d --name php2shell-vm -p 80:80 -v "$PWD/payloads:/payloads:ro" php2shell-lab:8.4.26

# watch the access log (it records upstream response times)
docker exec php2shell-vm tail -f /var/log/nginx/access.log

# restart just one daemon like on a real VM
docker exec php2shell-vm supervisorctl restart php-fpm
```

Useful surfaces inside the app:

* `GET /` — the dashboard (server-rendered metrics, charts, logs)
* `GET /index.php?api=stats` — live telemetry JSON (poll drives the charts/logs)
* `GET /index.php?api=ping` — engine fingerprint (`php`, `sapi`)
* `GET /healthz` — nginx-level liveness (no PHP involved)
* *Runtime Environment* view — live `ini_get()` posture, extensions, uptime

## Rebuilding the CSS (UI development only)

The compiled Tailwind CSS is already embedded in `index.php` — no build step is
needed to run the lab. To restyle it:

```bash
cd php2shell-lab
mkdir -p .build && cd .build
npm init -y && npm install -D tailwindcss@3.4
printf '@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' > input.css
cat > tailwind.config.js <<'EOF'
module.exports = { darkMode: 'class', content: ['../index.php'] };
EOF
npx tailwindcss -c tailwind.config.js -i input.css -o app.css --minify
# then replace the contents of the first <style> block in index.php with app.css
```

## Troubleshooting

* **`manifest unknown` / tag not found for `php:8.4.26-fpm-alpine`** — pin any
  other pre-patch build via the build arg, e.g.
  `docker build --build-arg PHP_IMAGE=php:8.3.35-fpm-alpine -t php2shell-lab:8.3 .`
* **Port 80 busy on the host** — use `-p 8080:80`.
* **Container exits immediately** — check `docker logs php2shell-vm`; the image
  expects `/etc/supervisor/conf.d/supervisord.conf` (bundled) and starts
  `/usr/bin/supervisord -c ...` as the command.
* **Charts/logs don't stream** — the browser needs JS enabled; the poll endpoint
  is `/index.php?api=stats` (verify with curl).

## Teardown

```bash
docker rm -f php2shell-vm
docker rmi php2shell-lab:8.4.26
```
