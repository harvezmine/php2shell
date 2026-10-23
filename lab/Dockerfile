FROM php:8.4.26-apache
# Single prefork worker is required for deterministic heap grooming in this chain.
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork
RUN printf '%s\n' \
    'StartServers 1' 'MinSpareServers 1' 'MaxSpareServers 1' \
    'MaxRequestWorkers 1' 'MaxConnectionsPerChild 0' \
    > /etc/apache2/conf-enabled/zz-prefork.conf

COPY zz-poc.ini /usr/local/etc/php/conf.d/zz-poc.ini
COPY webroot/ /var/www/html/
RUN rm -f /var/www/html/index.html \
    && mkdir -p /var/www/html/out \
    && chown -R www-data:www-data /var/www/html/out \
    && chmod 777 /var/www/html/out \
    && mkdir -p /var/lib/php/sessions \
    && chown www-data:www-data /var/lib/php/sessions
