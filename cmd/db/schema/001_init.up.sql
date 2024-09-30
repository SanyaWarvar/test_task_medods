CREATE TABLE users(
    id UUID PRIMARY KEY,
    email varchar(255) NOT NULL UNIQUE,
    ip varchar(16) NOT NULL
);

CREATE TABLE tokens(
    id serial PRIMARY KEY,
    user_id UUID REFERENCES users(id) NOT NULL,
    token varchar(64) NOT NULL,
    exp_date timestamp NOT NULL
);