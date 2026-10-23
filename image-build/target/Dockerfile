# syntax=docker/dockerfile:1
ARG ALPINE_VERSION=3.22.1
FROM --platform=linux/386 alpine:${ALPINE_VERSION} AS php-build
ARG PHP_VERSION=8.2.34
RUN apk add --no-cache build-base autoconf automake libtool bison re2c apache2 apache2-dev libxml2-dev
COPY image-build/downloads/php-${PHP_VERSION}.tar.gz /usr/src/php.tar.gz
RUN mkdir -p /usr/src/php && tar -xzf /usr/src/php.tar.gz -C /usr/src/php --strip-components=1
WORKDIR /usr/src/php
# Docker's linux/386 userspace can still see an x86_64 uname. Pin both
# triplets so Zend selects the i386 assembly that matches the musl compiler.
RUN ./buildconf --force && ./configure \
    --build=i686-pc-linux-musl \
    --host=i686-pc-linux-musl \
    --prefix=/usr/local \
    --with-apxs2=/usr/bin/apxs \
    --with-config-file-path=/etc/php \
    --with-config-file-scan-dir=/etc/php/conf.d \
    --disable-all \
    --enable-session \
    --enable-filter \
    --disable-cgi \
    --disable-phpdbg \
    --without-pear \
    && make -j2 && make install \
    && test -x /usr/local/bin/php \
    && test -f /usr/lib/apache2/libphp.so \
    && /usr/local/bin/php -v \
    && ldd /usr/lib/apache2/libphp.so

FROM --platform=linux/386 alpine:${ALPINE_VERSION} AS target
ARG PHP_VERSION=8.2.34
ARG ALPINE_VERSION=3.22.1
ARG PHP_SOURCE_SHA256
ARG BUILD_EPOCH=0
RUN apk add --no-cache alpine-base openrc linux-lts apache2 iproute2 libxml2 libgcc
COPY --from=php-build /usr/local/ /usr/local/
COPY --from=php-build /usr/lib/apache2/libphp.so /usr/lib/apache2/libphp.so
COPY image-build/target/overlay/ /
COPY image-build/target/webroot/ /var/www/html/
COPY image-build/target/php.ini /etc/php/php.ini
COPY image-build/target/php.conf /etc/apache2/conf.d/05-php.conf
COPY image-build/target/90-cyber-range.conf /etc/apache2/conf.d/90-cyber-range.conf

RUN adduser -D -s /bin/sh lab \
    && mkdir -p /home/lab /var/www/html /var/log/apache2 /run/apache2 /etc/cyber-range \
    && printf 'RANGE{UNPROVISIONED}\n' >/var/www/html/flag.txt \
    && chown -R root:apache /var/www/html \
    && find /var/www/html -type d -exec chmod 0755 {} \; \
    && find /var/www/html -type f -exec chmod 0644 {} \; \
    && chown root:apache /var/www/html /var/www/html/flag.txt \
    && chmod 0775 /var/www/html && chmod 0640 /var/www/html/flag.txt \
    && chmod 0755 /usr/local/bin/labctl /usr/local/bin/lab-login /usr/local/bin/root-control-login /etc/local.d/cyber-range.start /etc/init.d/cyber-range /init \
    && sed -i 's/^LoadModule mpm_/#&/' /etc/apache2/httpd.conf \
    && echo 'LoadModule mpm_prefork_module modules/mod_mpm_prefork.so' >>/etc/apache2/httpd.conf \
    && for service in devfs dmesg mdev hwdrivers; do rc-update add "$service" sysinit; done \
    && for service in hwclock modules sysctl hostname syslog bootmisc; do rc-update add "$service" boot; done \
    && rc-update add killprocs shutdown \
    && rc-update add cyber-range default \
    && cat >/etc/inittab <<'EOF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
tty1::respawn:/sbin/getty -n -l /usr/local/bin/lab-login 38400 tty1 linux
ttyS0::respawn:/sbin/getty -n -l /usr/local/bin/root-control-login 115200 ttyS0 vt100
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

RUN { \
      echo 'schema=1'; \
      echo "alpine_version=${ALPINE_VERSION}"; \
      echo 'architecture=x86 (32-bit)'; \
      echo "php_source_version=${PHP_VERSION}"; \
      echo "php_source_sha256=${PHP_SOURCE_SHA256}"; \
      echo 'php_sapi=Apache 2.0 handler (mod_php), prefork'; \
      echo 'php_configure=--build=i686-pc-linux-musl --host=i686-pc-linux-musl --disable-all --enable-session --enable-filter --disable-cgi --disable-phpdbg --with-apxs2=/usr/bin/apxs'; \
      echo "libphp_sha256=$(sha256sum /usr/lib/apache2/libphp.so | awk '{print $1}')"; \
      echo "source_date_epoch=${BUILD_EPOCH}"; \
      echo 'cve_reproduction_status=unverified-for-this-32-bit-build'; \
    } >/etc/cyber-range/build-info \
    && ldd /usr/lib/apache2/libphp.so | grep -q 'not found' && exit 1 || true \
    && /usr/local/bin/php -v \
    && /usr/local/bin/php -r 'exit(PHP_VERSION === getenv("PHP_VERSION") && ini_get("memory_limit") === "128M" ? 0 : 1);' \
    && httpd -t
