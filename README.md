# openam-auth-radius

*Extensions Made to OpenAM's Radius Library*

The code in this repo contains enhancements to OpenAM's original RADIUS authentication module. That module enabled
OpenAM to act as a RADIUS client and delegate authentication to a remote RADIUS server. The enhancements in this repo
enable OpenAM to be a RADIUS server for other RADIUS clients who wish to delegate authentication to it and take 
advantage of the available rich set of authentication modules where that is possible. Some modules clearly can not be
used by RADIUS clients such as any related directly to http constructs such as cookies. But others can be such as those
sending and SMS One Time Passcode for performing multi-factor RADIUS authentication.

To use this server functionality, constructs in OpenAM's admin console need to be added so that the server can obtain
its configuration. Steps for adding those constructs into the UI are found in [the resources directory](src/main/resources).

To exercise the RADIUS support a __ConsoleClient__ command line tool is also available. It allows a user to authenticate
to openAM using the RADIUS protocol by providing simple prompts on the command line and translating user input to
corresponding requests to the server. To use this tool the jar is crafted as an executable jar that uses this
ConsoleClient as its main class. To use it Run the following command:

    java -jar <path-to-jar>

When starting up it will print out its build information indicating its version and build date. Following that information
it will prompt the user to add a __radius.properties__ file in the current directory with the indicated properties:

    java -jar target/openam-auth-radius-1.0.1-SNAPSHOT.jar
    Jan 27, 2015 9:13:26 AM com.sun.identity.authentication.modules.radius.server.config.RadiusServiceStarter logModuleBuildVersion
    INFO: Loaded OpenAM Authn Radius Module = 1.0.1-SNAPSHOT built 2015-01-26 23:43 UTC

    Jan 27, 2015 9:13:26 AM com.sun.identity.authentication.modules.radius.server.config.RadiusServiceStarter logModuleBuildVersion
    INFO: Loaded OpenAM Authn Radius Module = 1.0.1-SNAPSHOT built 2015-01-26 23:43 UTC

    Missing required config file 'radius.properties' in current directory /Users/markboyd/git/openam/openam-authentication/openam-auth-radius/.
    Must Contain:
     secret=<shared-secret-with-server>
     host=<hostname-or-ip-address>
     port=<port-on-target-host>

    May Contain:
     show-traffic=true

The shared secret must match exactly including case the value specified for the RADIUS Client configured in the console
for the ConsoleClient. The host can be either a DNS name or an IP address. The port must match the port set for the
RADIUS server in openAM's console.

Once you have the radius.properties file defined the ConsoleClient will prompt for Username and Password. This must be a
user in OpenAM's backing user store. For my testing where I use embedded OpenDJ I created a user __boydmr__ in the root
realm. The username is also important in that it will be passed to the ldsaccount service to translate to a mobile phone
number. So it should match a username known by ldsaccount.

Once username and password are entered the ConsoleClient will connect to the RADIUS server and attempt to authentication
via username and password. If other modules are included in the chain then each field required by that module will be
conveyed back to the ConsoleClient and it will prompt for each additional field. Once all have been entered then it will
finish authenitcation against that module. This  continues until the user fails to provide proper values required by each
module in the chain or successfully authenticates to all modules in the chain.

As requests arrive at the Server log entries are made in catalina.out that can be used to troubleshoot problems with configuration.


# Questions?

If you have questions send them to Mark Boyd
at boydmr@ldschurch.org.

