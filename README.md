# asd (a simple dataencryptiontool) 

Boring straightforward password-based directory encryption. No options,
no key management, just to quickly exchange encrypted files without
having to dealing with GPG, OpenSSL, archivers' encryption, etc. 

Encrypt a directory (AES128-GCM'd uncompressed tar archive):
```
asd <directory>
``` 
You'll be asked for a password, `directory` will be deleted.

Decrypt a file (and extracting the tar archive):
```
asd <file>
```
You'll be asked for a password, `file` will be deleted.



