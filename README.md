# Portal API
The python API for the Portal UI project

## Preconditions
- Dependencies
```
pip install flask flask-cors flask-session sqlalchemy flask-sqlalchemy psycopg2-binary
```
- A PostgreSQLFlexibleServer in Azure
- Configure the app details using config.json

### (Optional) Setup SAML 2.0 SSO IdP
The Identity Provider can be any. Below is how to configure AzureAD and Google as IdP.

#### AzureAD
- Azure Console | Enterprise Applications | New custom app | Add Users | Single sign on | Basic SAML Configuration | Set Identifier (Entity ID); Reply URL (Assertion Consumer Service URL); logout url | Download Federation Metadata XML (IdP metadata XML)

#### Google
- Google Admin Console | Apps | Web and mobile apps | Add App |  Add custom SAML app | Download the IdP metadata XML | Set Entiry ID; ACS URL; Name ID = email; attribute mapping: first name = givenname, last name = surname, primary email = emailaddress | Add users via groups


### (Optional) Setup SAML 2.0 SSO Login locally
Here is how to setup SAML 2.0 SSO login using Azure AD

- To use SAML generate your private and public key, a cert and use the base64 one liners in the saml_settings.json
```
# Generate private key
openssl genrsa -out private_key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365

# Base64 encode the private key
openssl base64 -in private_key.pem -out private_key_base64.pem

# Base64 encode the certificate
openssl base64 -in certificate.pem -out certificate_base64.pem

# Remove new lines from the base64 encoded private key
tr -d '\n' < private_key_base64.pem > private_key_base64_single_line.pem

# Remove new lines from the base64 encoded certificate
tr -d '\n' < certificate_base64.pem > certificate_base64_single_line.pem
```
- Set in saml_*.json sp.x509cert and sp.privateKey out ofr certificate_base64_single_line.pem and private_key_base64_single_line.pem respectively
- Set in saml_*.json the sp.entityId to a dev URL of your liking
- Set in saml_*.json the sp.assertionConsumerService.url and sp.singleLogoutService.url using the same domain as in sp.entityId
- Set in the IdP the Entity ID
- Set in the IdP the sp.assertionConsumerService.url and sp.singleLogoutService.url
- Download the IdP Federation Metadata, remove new lines
- Copy from the metadata the entityId, single sign on url and single sign off url (usually the same as sign on), and thecertificate
- Paste the copied data into idp.entityId, idp.singleSignOnService.url, idp.singleLogoutService.url, and idp.x509cert into saml_*.json
```
cat metadata.xml | tr -d '\n'
```
- Run the app (listens on port 5000)
- Run ngrok
```
ngrok http 5000
```
- Reset in the IdP the sp.assertionConsumerService.url (/api/acs) and sp.singleLogoutService.url (/api/logout) replacing the domain with the one from ngrok
- Reset the proxy url for API requests in the frontend app (quasar.config.js)
- Every time you rerun ngrok you will have to reset the settings in the IdP and the frontend app

## Connect to  postgresql db
```
export PGHOST=***
export PGUSER=***
export PGPORT=5432
export PGDATABASE=postgres
export PGPASSWORD=***
psql
```

## Query db
```
# list dbs
\l
# connect to postgres db
\c postgres
# list tables
\dt
```

## Build
```
pip install -r requirements.txt
```

## Run in dev server
```
python app.py
```

## Run in docker
```
docker build -t portal-api .
docker run -d -p 5000:5000 --env-file .env portal-api
```
