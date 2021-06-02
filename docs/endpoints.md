# Raven - Endpoints

The Raven process includes a HTTP webserver that you can issue commands to.

> [!WARNING] Do not expose these endpoints as the implementation stands. The endpoints are not authenticated.

- **/forcerefresh** Regenerates all the SealedSecret's from Vault. 