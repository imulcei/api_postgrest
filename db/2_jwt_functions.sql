-- Permet d'encoder un tableau d'octets (BYTE ARRAY) contenant les données d'un JWT en chaîne de caractères sans 
-- "data" correspond au HWT à encoder
CREATE OR REPLACE FUNCTION api.jwt_url_encode(data BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    -- Les données en base64
    base64_text TEXT;
    -- base64 -> string sans caractères spéciaux d'URL
    -- par exemple '+' dans une URL est traité comme un espace
    -- '/' est utilisé pour séparer les parties d'une URL
    -- '=' est utilisé pour "padding" (la complétion d'une URL)
    url_safe_jwt TEXT;
BEGIN
    -- Encodage : on transforme les données en chaîne de caractères BASE64
    -- Plus d'information sur la base64 : https://fr.wikipedia.org/wiki/Base64
    base64_text := encode(data, 'base64');

    -- Transformation de la chaîne de caractères en BASE64
    -- afin de changer les caractères spéciaux pouvant poser problème pour les URL:
    -- '+' devient '-'
    -- '/' devient _
    -- '=' supprimé
    --  '\n' supprimé
    --
    -- Fonctionnement de la fonction "translate" : translate(source_string, from_chars, to_chars)
    -- les caractères '+' et '/' (premiers de 'from_chars') on des correspondances avec les 2 premiers caractères de 'to_chars'
    -- ils sont donc remplacés.
    -- Les caractères '=' et '\n' n'ont pas de correspondance (aucun caractères en 3ème et 4ème position), ils sont donc supprimés de 'source_string'
    -- Le 'E' avant le début de la string permet de considérer les caractères spéciaux tels que '\n'.
    url_safe_jwt := translate(base64_text, E'+/=\n', '-_');

    RETURN url_safe_jwt;
END;
$$;

-- Ci-dessous la version en SQL
-- CREATE OR REPLACE FUNCTION api.jwt_url_encode(data BYTEA)
--   RETURNS TEXT
-- LANGUAGE SQL
-- AS $$
-- 	SELECT translate(encode(data, 'base64'), E'+/=\n', '-_'); -- 
-- $$;


-- Calcule la signature d'un jeton JWT
-- cette signature s'effectue à l'aide d'une clé secrète (paramètr "secret") et est basé sur un algorithme de hashage reconnu
--
-- Le HMAC est un code d'authentification d'un message et permet d'attester de la source du JWT (le serveur)
-- Il est basé sur une fonction de hachage crytographique couplé à une clé secrète.
-- Le site suivant permet d'essayer une telle fonction : https://emn178.github.io/online-tools/sha256.html
CREATE OR REPLACE FUNCTION api.jwt_algorithm_sign(signables TEXT, "secret" TEXT, "algorithm" TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS
$$
DECLARE
    -- Nom de l'algorithme de hashage à utiliser
    algo_name TEXT;
    -- Signature calculée (tableau d'octets)
    "signature" BYTEA;
BEGIN
    -- Ce switch permet de récupéer le nom de l'algorithme utilisé comme attendu par la fonction HMAC
    CASE "algorithm"
        WHEN 'HS256' THEN algo_name := 'sha256';
        WHEN 'HS384' THEN algo_name := 'sha384';
        WHEN 'HS512' THEN algo_name := 'sha512';
        ELSE algo_name := NULL; -- Si non null alors hmac crashe.
    END CASE;

    -- Signature des données à signer (autrement dit, le contenu du JWT
    "signature" := hmac(signables, "secret", algo_name);

    -- On encode le résultat en données exploitables dans une URL ou un header de requête
    -- C'est la RFC qui indique qu'il faut que le JWT soit "url safe", voici l'extrait indiquant cette information :
    -- A JWT is represented as a sequence of URL-safe parts separated by
    -- period ('.') characters.  Each part contains a base64url-encoded
    -- value.
    --
    -- Les RFC imposent le respect.
    RETURN api.jwt_url_encode(signature);
END;
$$;

-- Ci-dessous la version en SQL
-- CREATE OR REPLACE FUNCTION api.jwt_algorithm_sign(signables TEXT, secret TEXT, algorithm TEXT)
--   RETURNS TEXT
-- LANGUAGE SQL
-- AS $$
-- WITH
--     alg AS (
--      SELECT CASE
--      WHEN algorithm = 'HS256'
--        THEN 'sha256'
--      WHEN algorithm = 'HS384'
--        THEN 'sha384'
--      WHEN algorithm = 'HS512'
--        THEN 'sha512'
--      ELSE '' END AS id) -- hmac throws error
-- SELECT api.jwt_url_encode(hmac(signables, secret, alg.id))
-- FROM alg;
-- $$;

-- Création d'un JWT
-- Plus d'informations sur le contenu d'un JWT : https://jwt.io/
CREATE OR REPLACE FUNCTION api.jwt_sign(payload JSON, "secret" TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    -- Header du JWT encodé en base64url
    header_encoded TEXT;
    -- Payload du JWT encodé en base64url
    payload_encoded TEXT;
    -- Informations utilisée pour calculer la signature
    signables TEXT;
    -- Signature du JWT
    "signature" TEXT;
BEGIN
    -- Construction et encodage du header
    -- le header définit le type d'algorithme à utiliser pour claculer la signature HMAC
    header_encoded := api.jwt_url_encode(convert_to('{"alg":"HS256","typ":"JWT"}', 'utf8'));

    -- Construction et encodage du "payload" (souvent les informations utilisateur)
    -- notez la transformation du JSON en TEXT
    payload_encoded := api.jwt_url_encode(convert_to(payload::TEXT, 'utf8'));

    -- Concaténation des 2 premières parties qui serviront de source au calcule de la signature
    signables := header_encoded || '.' || payload_encoded;

    -- Récupération de la signature
    "signature" := api.jwt_algorithm_sign(signables, "secret", 'HS256');

    -- On retourne le JWT complet : header.payload.signature
    RETURN signables || '.' || signature;
END;
$$;

-- Ci-dessous la version en SQL
-- Création d'un JWT à partir d'une clef secrète
-- PAYLOAD : email + role ? ??
-- CREATE OR REPLACE FUNCTION api.jwt_sign(payload JSON, secret TEXT)
-- RETURNS TEXT
-- LANGUAGE SQL
-- AS $$
-- WITH
--     header AS (
--       SELECT api.jwt_url_encode(convert_to('{"alg":"HS256","typ":"JWT"}', 'utf8')) AS data),
--     payload AS (
--       SELECT api.jwt_url_encode(convert_to(payload :: TEXT, 'utf8')) AS data),
--     signables AS (
--       SELECT header.data || '.' || payload.data AS data
--       FROM header, payload
--   )
-- SELECT signables.data || '.' || api.jwt_algorithm_sign(signables.data, secret, 'HS256')
-- FROM signables;
-- $$;