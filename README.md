# burp java signer

## Description
The purpose of this extension is to easily mitm java applications which require signing of the jar files (jnlp projects with self checking)


## Usage
Install the provided jar file or compile with maven using assembly:single
Add the java jdk folder for loading java jar files (C:\Program Files\Java\jdk1.8.xxxx)

Browse any jar/jnlp application with the burp proxy while using it
In order to enjoy a full mitm experience, install the created pkcs12 keystore as burp's certificate and configure java to use the burp proxy.

Have Fun!!!

_Note: You must install Burp Suite (either the community or pro version) first.  Then download the latest burp-paramalyzer release (.jar file) and install it through the Burp Extender tab._