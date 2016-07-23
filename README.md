# Burp Java Signer

## Description
The purpose of this extension is to easily mitm java applications which require signing of the jar files
the plugin performs this by rewriting the manifest file without ruining other data inside and replacing all other signatures inside

The plugin works for a special case I needed to change stuff inside a jnlp jar application, this was not tested yet on other applications
I would be glad to recieve some feedback and bug reports :)


## Usage
Install the provided jar file or compile with maven using assembly:single
Add the java jdk folder for loading java jar files (C:\Program Files\Java\jdk1.8.xxxx)

Browse any jar/jnlp application with the burp proxy while using it
In order to enjoy a full mitm experience, install the created pkcs12 keystore as burp's certificate and configure java to use the burp proxy.

Have Fun!!!

**Rotem Bar** - **rotemb@gmail.com**