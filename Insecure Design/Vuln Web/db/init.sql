create database IF NOT EXISTS test;
ALTER DATABASE test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

use test;

drop table if EXISTS users;

create TABLE users (
    id int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username varchar(30) NOT NULL,
    password varchar(40) NOT NULL
);

INSERT into users (username, password) VALUES ('admin', '123456');