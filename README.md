# ssd-jwt-auth
Repo to implement the SSD service-to-service JWT-auth package

https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit

All services in SSD authenticate with JWTs.

This package is used in 2 places. Token-Machine uses this to create JWTs. ssd services use this to validate JWTs (verifyer.go). ssg-gate creates user tokens by calling the token-machine API. Some service will eventually create service JWTs as well.

It also has a middleware that can be used by all services, to transparently validate tokens. ssd-gate uses its own middleware has there are other alternate forms of auth.

Communications fall in these categories:
- External systems to services within SSD :These will typically go through the ssd-gate where they will be authenticated
- SSD services to other SSD Services: These will use the "internal-account" type to increase the priviledges Or can use the token received to support a call
- UI to SSD-Gate: As secure cookie is already implemented, we will continue to use it. JWTs with large number groups cause error in Session cookie length

Token creation:
- UI will provide options to create tokens specific to an integration
- UI will provide option generic user token can be used in automation
- Library will provide ability to create Internal JWTs only.
- User and service tokens can only be created by ssd-gate post authentication. SSD services can request service-token by creating an internal-account with their service-name

Library Functions
- Authnenticate
- Get SSDToken Object, with std interface for all attributes
- Get Groups from token
- Get Token Type
- Get UserName/service-name
- Get Organization ID
- InstanceID (service accounts)
- IsAdmin : true allows unconditional access

