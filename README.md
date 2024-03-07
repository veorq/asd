# asd (a simple dataencryptiontool) 

Sraightforward password-based directory encryption. No options, no key
management, just to quickly exchange encrypted files without
having to dealing with GPG, OpenSSL, archivers' encryption, etc. 

Encrypt a directory (AES128-GCM'd uncompressed tar archive):
```
asd <directory>
``` 

Decrypt a file (and extracting the tar archive):
```
asd <file>
```

The key is derived from a password using Argon2id.
