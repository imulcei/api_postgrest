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



CREATE OR REPLACE FUNCTION api.jwt_url_encode(data BYTEA)
  RETURNS TEXT
LANGUAGE SQL
AS $$
	SELECT translate(encode(data, 'base64'), E'+/=\n', '-_'); -- 
$$;

CREATE OR REPLACE FUNCTION api.jwt_algorithm_sign(signables TEXT, secret TEXT, algorithm TEXT)
  RETURNS TEXT
LANGUAGE SQL
AS $$
WITH
    alg AS (
     SELECT CASE
     WHEN algorithm = 'HS256'
       THEN 'sha256'
     WHEN algorithm = 'HS384'
       THEN 'sha384'
     WHEN algorithm = 'HS512'
       THEN 'sha512'
     ELSE '' END AS id) -- hmac throws error
SELECT api.jwt_url_encode(hmac(signables, secret, alg.id))
FROM alg;
$$;

-- Création d'un JWT à partir d'une clef secrète
-- PAYLOAD : email + role ? ??
CREATE OR REPLACE FUNCTION api.jwt_sign(payload JSON, secret TEXT)
RETURNS TEXT
LANGUAGE SQL
AS $$
WITH
    header AS (
      SELECT api.jwt_url_encode(convert_to('{"alg":"HS256","typ":"JWT"}', 'utf8')) AS data),
    payload AS (
      SELECT api.jwt_url_encode(convert_to(payload :: TEXT, 'utf8')) AS data),
    signables AS (
      SELECT header.data || '.' || payload.data AS data
      FROM header, payload
  )
SELECT signables.data || '.' || api.jwt_algorithm_sign(signables.data, secret, 'HS256')
FROM signables;
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
	
	SELECT api.jwt_sign(row_to_json(r), 'jaime_lesmirabelles_etleslasagnes') /*AS token*/
	FROM (SELECT _role AS role, login.email AS email, extract(epoch FROM now())::integer + 60*60 AS exp) r INTO token;
END;
$$;

GRANT SELECT ON api.users TO web_anon;
GRANT SELECT ON api.users TO authenticator;
GRANT EXECUTE ON FUNCTION api.login(text, text) TO web_anon;
GRANT EXECUTE ON FUNCTION api.user_role(text, text) TO web_anon;

INSERT INTO api.users(email, pwd, role) VALUES ('lucie@mail.com', 'jaimelesmirabelles123', 'todo_user');