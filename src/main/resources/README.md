# Adding RadiusClientService to OpenAM Console

The directory includes files for adding configuration constructs to OpenAM's console for configuring the port on which
to listen for RADIUS Access-Requests, enabling listening, and defining the set of allowed clients from which we will 
accept requests. To expose these items in the UI the following steps are taken assuming that I am building this
module outside of the product as a whole and adding it into an already deployed instance of openAM rather than having
the module build from scratch as part of building openAM itself. For that case we'll have to add documentation
when we get to that point.  

* Build the jar and add it into the deployed webapp-root/WEB-INF/lib directory removing the existing openam-auth-radius
jar. This will get our properties file where it needs to be for the console to load its labels and will make available the 
DefaultClientSecretGenerated referenced in the service's descriptor file.

* Restart tomcat so that it sees the new jar.

* Register our service to show in the console by Signing in as amadmin and accessing /openam/ssoadm.jsp or suitable path
for your installation. If the jsp isn't available, activate it by authenitcating
to openAM as an administrator, proceeding to Configuration tab, Servers and Sites sub-tab, selecting server name,
selecting the Advanced tab, pressing the Add button, and creating a property of __ssoadm.disabled = false__. Once
accessible, select the __create-svc__ command, paste in the contents of the __amRadiusServer.xml service descriptor file__ and 
press submit. Thereafter, if you ever need to adjust use the __update-svc__ command to replace the contents of the file. 

Registering the service to show in the console is instantaneous. View the constructs by going to the Configuration tab,
the Global sub-tab, and noting the inclusion of a new __RADIUS Server__ in the __Global Properties__ table. Select that
item and you can now define RADIUS Clients, set the port on which to listen for requests, and enable the RADIUS server.


# Questions?

If you have questions send them to Mark Boyd
at boydmr@ldschurch.org.

