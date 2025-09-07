New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
deno serve --allow-net --cert=./localhost.crt --unstable-kv --allow-env index.js
