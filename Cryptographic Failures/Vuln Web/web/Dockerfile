FROM php:5.6-apache

RUN apt-get update && apt-get install libmcrypt-dev -y
RUN docker-php-ext-install mysql pdo pdo_mysql mcrypt && docker-php-ext-enable mysql
    
WORKDIR /var/www/html/
COPY ./html .