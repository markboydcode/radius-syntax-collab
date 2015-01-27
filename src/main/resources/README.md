# Adding RadiusClientService to OpenAM Console

The directory includes files for adding configuration constructs to OpenAM's console for configuring the port on which
to listen for RADIUS Access-Requests, enabling listening, and defining the set of allowed clients from which we will 
accept requests. The current build embeds the radius jar into the WAR so radius runtime artifacts are readily availble
to OpenAM. However, the following step must be taken to add the configuration constructs into the console.

* Register the service descriptor file __amRadiusServer.xml__ by Signing in as amadmin and accessing /openam/ssoadm.jsp or suitable path
for your installation. If the jsp isn't available, activate it by authenitcating
to openAM as an administrator, proceeding to Configuration tab, Servers and Sites sub-tab, selecting server name,
selecting the Advanced tab, pressing the Add button, and creating a property of __ssoadm.disabled = false__. Once
accessible, select the __create-svc__ command, paste in the contents of the __amRadiusServer.xml service descriptor file__ and 
press submit. Thereafter, if you ever need to adjust use the __update-svc__ command to replace the contents of the file. 

Registering the service to show in the console is instantaneous. View the constructs by going to the Configuration tab,
the Global sub-tab, and noting the inclusion of a new __RADIUS Server__ in the __Global Properties__ table. Select that
item and you can now define RADIUS Clients, set the port on which to listen for requests, enable the RADIUS server, and
press the Save button.

You'll immediately see log entries in catalina.out that show the RADIUS server starting up. Some parts have been snipped
out in the content below to make it more clear:

    27-Jan-2015 09:33:18.604 INFO [RADIUS-RadiusServiceStarter] <snip/> RADIUS Config Changed. Loading...
    27-Jan-2015 09:33:18.605 INFO [RADIUS-RadiusServiceStarter] <snip/> --- Loaded Config ---
    [RadiusServiceConfig YES 1812 P( 1, 10, 10, 10), C( 127.0.0.1=local console client, letmein, true, <snip/>.OpenAMAuthHandler, {realm=/, chain=ldapserviceAndSmsotp})]

    27-Jan-2015 09:33:18.605 INFO [RADIUS-RadiusServiceStarter] <snip/> RADIUS service enabled. Starting Listener.
    27-Jan-2015 09:33:18.606 INFO [RADIUS-1812-Listener] <snip/> RADIUS Listener is Active.
    Port              : 1812
    Threads Core      : 1
    Threads Max       : 10
    Thread Keep-alive : 10 sec
    Request Queue     : 10

Note that the logging also dumps in very concise form each clien't configuration. And not in this case that the IP
address for the single defined client is ___127.0.0.1__. If any RADIUS requests are received before any clients are
configured or if the configured clients don't match the IP
address of the incoming packets the RADIUS server will log the attempt and silently drop to packet as specified in the RFC:

    27-Jan-2015 09:45:25.004 WARNING [RADIUS-1812-Listener] <snip/>
    No Defined RADIUS Client matches IP address /127.0.0.1. Dropping request.

This log message is very useful in that it specifies the exact value of the client's IP address that must be specified
in the client configuration page for packets from that client to be accepted for authentication. Once the IP address for
the defined client is changed to __/127.0.0.1__ the packets are now accepted and authentication against modules in the
specified chain __ldapserviceAndSmsotp__ now begins.

# Questions?

If you have questions send them to Mark Boyd
at boydmr@ldschurch.org.

