SecureRepo project
====
(reading from citizen's id smartcard; JNI C-Java; digital signatures)

Implementing a file repository that provides confidentiality and authenticity guarantees to valid
users. The access to the repository is assumed free, but only users with a cypher blackbox may obtain
valid data. With no access control it is possible to corrupt the contents, but it was out of scope
of this work. 

Authentication is done by a digital signature validation, using the authentication private key present
in the citizen's card (cartao do cidadao). The private key is never extracted, the pteidlib allows 
the card to sign or validate a signature via a card reader. The public key is contained in the 
certificate stored in a database.

Confidentiality of the files is guaranteed by the symmetric cypher implemmented by the blackbox (in 
C) - to simplify, the cypher used was a simple XOR with all-1's.
When obtaining the file, it is first decyphered and then the signature is validated. When a file is 
stored, it is first signed and then cyphered. Only blackbox users may generate valid signatures.

- Using Eclipse, use the jar-build target to produce the executable jar

- Before running, create the folders:
    - LocalRepo (local repository)
    - SecureRepo ("Remote" repository where the files are kept safe)
    - SecureRepo/authentication (stores author's data and the last signature for each file)
    - certificates (the State database where national citizen's certificates are stored)
	
- Go to the build folder where the jar is, and run:
    java -Djava.library.path=<path of pteid_jni>:<path of the libs> -jar SecureRepo.jar
    Example:
    java -Djava.library.path=/usr/local/lib/pteid_jni:/home/kurt/workspace/SecureRepo/libs -jar SecureRepo.jar




