package main

const (
	Query = `
CREATE TABLE IF NOT EXISTS Users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(32) NOT NULL UNIQUE,
    password VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS Sessions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS Circles (
    id SERIAL PRIMARY KEY,
    id_user INTEGER NOT NULL,
    name VARCHAR(64) NOT NULL,
    FOREIGN KEY (id_user) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS SessionsCircles (
    id_session INTEGER NOT NULL,
    id_circle INTEGER NOT NULL,
    PRIMARY KEY (id_session, id_circle),
    FOREIGN KEY (id_session) REFERENCES Sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (id_circle) REFERENCES Circles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS SuperKeys (
    id SERIAL PRIMARY KEY,
    superkey VARCHAR(64) NOT NULL UNIQUE,
    id_user INTEGER NOT NULL,
    FOREIGN KEY (id_user) REFERENCES Users(id) ON DELETE CASCADE
);
`
)
