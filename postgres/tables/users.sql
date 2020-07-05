BEGIN TRANSACTION;

DROP TABLE IF EXISTS users;

COMMIT;

BEGIN TRANSACTION;

CREATE TABLE users (
    id serial PRIMARY KEY,
    name VARCHAR(100),
    email text UNIQUE NOT NULL,
    entries BIGINT DEFAULT 0,
    joined TIMESTAMP NOT NULL,
    age INTEGER,
    pet VARCHAR(100)
);

COMMIT;