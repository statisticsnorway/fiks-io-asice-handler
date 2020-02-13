# fiks-io-asic-handler
![GitHub](https://img.shields.io/github/license/ks-no/fiks-io-asice-handler)
[![Maven Central](https://img.shields.io/maven-central/v/no.ks.fiks/fiks-io-asice-handler.svg)](https://search.maven.org/search?q=g:no.ks.fiks%20a:fiks-io-asice-handler)
![GitHub last commit](https://img.shields.io/github/last-commit/ks-no/fiks-io-asice-handler.svg)
![GitHub Release Date](https://img.shields.io/github/release-date/ks-no/fiks-io-asice-handler.svg)

Wrapper for DIFI's AsicE library
## Example
```java
final ExecutorService executor = // create Executor service to be used internally (minimum 2 threads)
final PrivateKey privateKey = // a java.security.PrivateKey instance to be used for decryption 
final KeyStoreHolder keyStoreHolder = KeyStoreHolder.builder()
    .withKeyStore(keyStore) // a java.security.KeyStore to be used to get encryption certificate from
    .withKeyStorePassword("keystorepassword")
    .withKeyAlias("keyAlias")
    .withKeyPassword("keyPassword")
    .build();
final AsicHandler asicHandler = AsicHandler.builder()
    .withPrivatNokkel(privateKey)
    .withExecutorService(executor)
    .withKeyStoreHolder(keyStoreHolder)
    .build();
```
