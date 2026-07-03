# playReady

https://forum.videohelp.com/threads/416567-PRD-Devices

~~~
Today at 6:12 PM
I am dumb - why is it 3 files instead of 2
 — 
Today at 6:12 PM
because
zgpriv is the MPK = model private key
bgroupcert.dat is the base certificate
when you provision a device, you use the base certificate and "add" a leaf
certificate to the base certificate which makes it the certificate chain
inside of the leaf you define the encryption key and signing key and store the
public values of them
you only need to provision it once, once done you save the private keys and use
them instead
what a licensing server does is takes the sign key public key value you provide
it and checks it against the signature that you sign in the challenge
checks if its correct
then decrypts your device from the aes and iv you encrypt with the wmrm public
key
reads the device for your device cert, checks if its correct then it will
encrypt the decryption key in the license response with the encrypting key you
defined
and it allows you to decrypt it with the private value you have saved
~~~

https://github.com/lossui011/Shield-Playready-SL2000
