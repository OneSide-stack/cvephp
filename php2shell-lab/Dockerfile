# syntax=docker/dockerfile:1

# ============================================================================
#  PHP2Shell analysis lab — all-in-one "VM-style" container
# ----------------------------------------------------------------------------
#  Vulnerable runtime under test:
#      PHP 8.4.26 (fpm-fcgi) — last 8.4 release BEFORE the PHP2Shell fixes
#      CVE-2026-109618  RCE via out-of-memory corruption   (CVSS v4.0 9.2)
#      CVE-2026-109619  RCE via stale global state         (CVSS v4.0 9.2)
#      (fixed upstream in 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35)
#
#  Topology (single container, supervised like a VM):
#      supervisord (PID 1)
#        ├─ php-fpm   127.0.0.1:9000   (pool "www")
#        └─ nginx     0.0.0.0:80  ──(fastcgi)──► php-fpm
#
#  ⚠  DELIBERATELY VULNERABLE — for isolated lab/analysis use only.
#     Never expose this container to a network you care about.
# ============================================================================

# Override with --build-arg PHP_IMAGE=<tag> if you want to pin a different
# pre-patch build (e.g. php:8.3.35-fpm-alpine or php:8.2.34-fpm-alpine).
ARG PHP_IMAGE=php:8.4.26-fpm-alpine
FROM ${PHP_IMAGE}

LABEL org.opencontainers.image.title="php2shell-lab" \
      org.opencontainers.image.description="Vulnerable all-in-one VM-style container (nginx + PHP-FPM under Supervisor) for analysing PHP2Shell (CVE-2026-109618 / CVE-2026-109619)" \
      org.opencontainers.image.licenses="MIT" \
      io.php2shell.target-php="8.4.26" \
      io.php2shell.cves="CVE-2026-109618,CVE-2026-109619" \
      io.php2shell.base-image="${PHP_IMAGE}"

# ── OS packages: nginx (front door) + supervisor (VM init / process mgr) ──
RUN apk add --no-cache nginx supervisor

# ── configuration ────────────────────────────────────────────────────────────
COPY nginx.conf       /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY php2shell.ini    /usr/local/etc/php/conf.d/90-php2shell.ini

# ── application bundle: the complete UI (HTML + CSS + JS + PHP API) ships
#    as a single functional index.php in /var/www/html ──────────────────────
COPY --chown=www-data:www-data index.php /var/www/html/index.php

# ── lab-only impact chain runner (SIMULATION — read the file header) ───────
# Models the lifetime violation each advisory describes so the guided room can
# run recon -> bailout -> stale reuse -> code execution -> flag. It is not a
# weaponised exploit and it refuses to run on a patched engine.
COPY --chown=www-data:www-data lab-exploit.php /var/www/html/lab-exploit.php
# Full guided room, bundled into the image for reference from inside the
# container (the in-app Solution tab is rendered from index.php).
# Build from inside php2shell-lab/: `docker build -t php2shell-lab:8.4.26 .`
# (the build context is this folder, so WALKTHROUGH.md must be present here).
COPY WALKTHROUGH.md /var/www/html/WALKTHROUGH.md

# runtime dirs, permissions, log destinations, lab flags + simulator switch
#   /var/www/html/.lab-flag-*  → readable only by code execution (nginx denies dotfiles)
#   /opt/php2shell/...         → presence of the marker enables the chain runner
RUN mkdir -p /var/log/supervisor /var/log/nginx /var/lib/nginx/tmp /run /opt/php2shell /tmp/php2shell \
    && printf 'PHP2SHELL{109618-oom-bailout-reused-worker-memory}\n' > /var/www/html/.lab-flag-109618 \
    && printf 'PHP2SHELL{109619-stale-worker-global-after-fatal}\n'  > /var/www/html/.lab-flag-109619 \
    && : > /opt/php2shell/impact-sim.enabled \
    && chown -R www-data:www-data /var/www/html /tmp/php2shell \
    && chmod 0755 /opt/php2shell && chmod 0644 /opt/php2shell/impact-sim.enabled

# the lab's only published port: the nginx front door
EXPOSE 80

# full-stack healthcheck: nginx → FastCGI → PHP-FPM → PHP engine
HEALTHCHECK --interval=15s --timeout=4s --start-period=12s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1/index.php?api=ping" || exit 1

# supervisord as PID 1: brings up php-fpm (priority 5) then nginx (priority 10)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
