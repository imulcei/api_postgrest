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