CREATE SCHEMA api; 

CREATE TABLE api.todos (
	id SERIAL NOT NULL PRIMARY KEY,
	done BOOLEAN NOT NULL DEFAULT FALSE,
	task TEXT NOT NULL,
	due TIMESTAMP
);

INSERT INTO api.todos (task) VALUES ('finish tutorial 0'), ('pat pat');

CREATE ROLE web_anon nologin;
GRANT USAGE ON SCHEMA api TO web_anon;
GRANT ALL ON api.todos TO web_anon;

CREATE ROLE authenticator noinherit login PASSWORD 'mysecretpassword';
GRANT web_anon TO authenticator;
GRANT USAGE ON SCHEMA api TO authenticator;
GRANT SELECT ON ALL TABLES IN SCHEMA api TO authenticator;

-- trusted user
CREATE ROLE todo_user nologin;
GRANT todo_user to authenticator;

GRANT USAGE ON SCHEMA api TO todo_user;
GRANT ALL ON api.todos to todo_user;


-- user storage
CREATE SCHEMA IF NOT EXISTS basic_auth;

create table
basic_auth.users (
  email    text primary key check ( email ~* '^.+@.+\..+$' ),
  pass     text not null check (length(pass) < 512),
  role     name not null check (length(role) < 512)
);


create role anon noinherit;
create role authenticator noinherit;
grant anon to authenticator;

