create database IF NOT EXISTS cbc;

use cbc;

CREATE TABLE IF NOT EXISTS users (
    login varchar(40) NOT NULL PRIMARY KEY,
    password varchar(40)
);

INSERT INTO `users` (login, password) VALUES ('admin', 'a946f5d49d28a635685adccb85072288');
