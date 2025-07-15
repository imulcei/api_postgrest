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

-- stocker les emails et pwd des users
CREATE TABLE api.users (
	email TEXT PRIMARY KEY CHECK (email ~* '^.+@.+\..+$'),
	pwd TEXT NOT NULL CHECK (length(pwd) < 512),
	role NAME NOT NULL CHECK (length(role) < 512)
);

CREATE OR REPLACE FUNCTION api.check_role_exists()
	RETURNS TRIGGER
	LANGUAGE plpgsql
AS $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_roles AS pr WHERE pr.rolname = new.role) THEN
		RAISE foreign_key_violation USING message = 'unknown database role' || new.role;
		RETURN null;
	END IF;
	RETURN new;
END;
$$;

CREATE CONSTRAINT TRIGGER ensure_user_role_exists
AFTER INSERT OR UPDATE ON api.users 
FOR EACH ROW 
EXECUTE PROCEDURE api.check_role_exists();

-- crypter les mots de passes
CREATE EXTENSION pgcrypto; 

CREATE OR REPLACE FUNCTION api.encrypt_pass() 
	RETURNS TRIGGER
	LANGUAGE plpgsql
AS $$
BEGIN
	IF tg_op = 'INSERT' OR new.pwd <> old.pwd THEN 
		new.pwd = crypt(new.pwd, gen_salt('bf'));
	END IF;
	RETURN new;
END;
$$;

CREATE TRIGGER encrypt_pass 
BEFORE INSERT OR UPDATE ON api.users 
FOR EACH ROW 
EXECUTE PROCEDURE api.encrypt_pass();

-- test de connexion
CREATE OR REPLACE FUNCTION api.user_role(email TEXT, pwd TEXT)
	RETURNS name
	LANGUAGE plpgsql
AS $$
BEGIN
	RETURN (SELECT role FROM api.users WHERE users.email = user_role.email AND users.pwd = crypt(user_role.pwd, users.pwd));
END;
$$;

-- CREATE EXTENSION pgjwt;

-- générer le JWL dans le SQL
CREATE OR REPLACE FUNCTION jwt_test(OUT token text)
	RETURNS TEXT
	LANGUAGE plpgsql
AS $$
BEGIN
	SELECT public.sign(row_to_json(r), 'jaime_lesmirabelles_etleslasagnes') AS token
	FROM (SELECT 'my_role'::TEXT AS role, extract(epoch FROM now())::INTEGER + 300 AS exp) r;
END;
$$;

-- connexion
CREATE OR REPLACE FUNCTION api.login(email text, pwd text, OUT TOKEN text) 
	LANGUAGE plpgsql
AS $$
DECLARE
	_role name; 
BEGIN
	SELECT api.user_role(email, pwd) INTO _role;
	IF _role IS NULL THEN
		RAISE invalid_password USING message = 'invalid user or password';
	END IF;
	
	SELECT public.sign(row_to_json(r), 'jaime_lesmirabelles_etleslasagnes') AS token
	FROM (SELECT _role AS role, login.email AS email, extract(epoch FROM now())::integer + 60*60 AS exp) r INTO token;
END;
$$;

GRANT SELECT ON api.users TO web_anon;
GRANT SELECT ON api.users TO authenticator;
GRANT EXECUTE ON FUNCTION api.login(text, text) TO web_anon;
GRANT EXECUTE ON FUNCTION api.user_role(text, text) TO web_anon;

INSERT INTO api.users(email, pwd, role) VALUES ('lucie@mail.com', 'jaimelesmirabelles123', 'todo_user');


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

