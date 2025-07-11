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
GRANT SELECT ON api.todos TO web_anon;

CREATE ROLE authenticator noinherit login PASSWORD 'mysecretpassword';
GRANT web_anon TO authenticator;