# openam-auth-radius

*Extensions Made to OpenAM's Radius Library*

The code in this repo contains enhancements to OpenAM's original RADIUS authentication module. That module enabled
OpenAM to act as a RADIUS client and delegate authentication to a remote RADIUS server. The enhancements in this repo
enable OpenAM to be a RADIUS server for other RADIUS clients who wish to delegate authentication to it and take 
advantage of the available rich set of authentication modules were that is possible. Some modules clearly can not be 
used by RADIUS clients such as any related directly to http constructs such as cookies. But others can be such as those
sending and SMS One Time Passcode for performing multi-factor RADIUS authentication.

To use this server functionality constructs in OpenAM's admin console need to be added so that the server can obtain
its configuration. Steps for adding those constructs into the UI are found in [the resources directory](src/main/resources).

Additionally, an initial Proof Of Concept (POC) standalone RADIUS service was provided to test the validity of using
OpenAM's codebase for fielding RADIUS client calls was constructed and now resides in [the poc package](src/main/java/com/sun/identity/authentication/modules/radius/server/poc).



# Questions?

If you have questions send them to Mark Boyd
at boydmr@ldschurch.org.

