FROM php:8.2-apache

RUN apt-get update && apt-get install -y \
    curl \
    libcurl4-openssl-dev \
    unzip \
    && apt-get clean

COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html
