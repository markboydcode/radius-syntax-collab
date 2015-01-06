# openam-auth-radius

*Extensions Made to OpenAM's Radius Library*

The code in this package contains a __multi-factor authentication Proof Of Concept (POC) for VPN__ with multiple channels available
and just-in-time provisioning directly by users.

OpenAM's radius library is an authentication module enabling OpenAM to act as a radius client and authenticate a user
against one or more remote radius servers via the radius protocol over UDP. The __base code__ checked into this repo is from
an SVN checkout of the __OpenAM codebase__ that shows __Revision 8525__ for the command 'svn info'. Looking at the set
of changes in the second commit to this repo shows the suite of changes made. These broadly fall into these categories:

* Enhance existing classes to support marshalling in both ways from an incoming UDP packet of bytes to a java object graph and
from a java object graph to an outgoing UDP packet of bytes.

* Adding support for NIO.

* Implementing a VPN multi-factor authentication Proof of Concept with just-in-time provisioning of a user's preferred
multi-factor channel. This is embodied in a listener for Radius connections and related classes to configure and manage
a state machine enabling a user's VPN client to carry on a conversation
through multiple request and response pages via sequential radius access-challenge responses.

* Supporting three multi-factor channels: __SMS delivered One Time Password (OTP)__ (see the server.SmsService class),
__Toopher__ native android and iPhone app using __cloud messaging__ (see the server.ToopherService class), and
__Text-to-speech Voice call__ delivered OTP (see the server.VoiceService class).

Since that check in the codebase has continued to progress adding radius server support into openam. As such the initial
POC code has been moved to this package for preservation. 

# Trying the Proof Of Concept

For a time the POC could be accessed with a cisco VPN client by typing into the client's drop down box containing the External
and Internal options this string, "216.49.183.25/radius", and pressing Connect. At some point this test endpoint will
go away so it may not work at the present time. To used the POC you would need to ask the infrastructure team to make
a text NAS endpoint available that points to a running instance of the POC. 

The POC code was enhanced to provide different Flows or tailored user interaction scenarios. The original POC flow is
available as the SampleFlows.POC_ORIGINAL_WITH_PROVISIONING_MENU flow and would have to be specified in the 
RadiusListener class's main() method. The last POC flow that was used was specifically tailored to reflect that 
anticipated scenario experienced by user once radius server functionality was finished in openam. That flow is the 
SampleFlows.SMS_PROD_DEMO_NO_PROVISIONING flow. In either flow please note, the password is not
being used so don't enter your real lds account password. Rather, that field is being used to trigger different experiences
for demo'ing.

For example, if the field is empty the original POC ignores any previously selected channel for your username and walks you through
the provisioning pages allowing you to set up your preferred channel. If any other value is entered into the password field
__and__ you have previously selected a preferred multi-factor channel then that channel will be executed to perform the
multi-factor step such as sending you and SMS or Voice delivered OTP or opening the Toopher application on your device
and asking for permission to access VPN.

In this fashion the original POC could always trigger the initial provisioning example or show how an existing channel is automatically
used. But __please note__ that this just-in-time provisioning flow was solely the creation of Mark Boyd and was meant only
to get people thinking that provisioning must be accomplished in some way before we can make serious progress on providing
a multi-factor authentication mechanism. That JIT approach was a rough experience and needs polishing if deemed desire-able.


# How Does It Work?

The POC was fired off with the following command line that includes dependent jars. Of note, the toopher jar was extracted
from the toopher demo and had all of its dependencies removed from within that standalone executable jar so that only the
toopher provided classes were included since it conflicted with the newer versions of http client. The -D parameters tell
http client to log the http on-the-wire bytes sent and received for help in troubleshooting the interactions with Toopher's,
Twilio's, and our own internal SMS services:

      java -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.SimpleLog
      -Dorg.apache.commons.logging.simplelog.showdatetime=true
      -Dorg.apache.commons.logging.simplelog.log.org.apache.http=DEBUG
      -Dorg.apache.commons.logging.simplelog.log.org.apache.http.wire=DEBUG
      -cp signpost-commonshttp4-1.2.jar:signpost-core-1.2.jar:json-20140107.jar:commons-logging-1.1.1.jar
        :commons-codec-1.6.jar:httpclient-4.3.3.jar:Toopher.jar:openam-auth-radius-20140802.jar
        :httpcore-4.3.2.jar com.sun.identity.authentication.modules.radius.server.poc.RadiusListener

In addition to running this Radius Server the Network Access Server at the ip address indicated above for trying the POC
had to be configured to use the Radius Protocol to speak to this service. Ultimately, the goal was to roll this into OpenAM
and configure clients, their flows, and channels (OpenAM's authentication modules) via OpenAM admin console which has
now been accomplished.


# For Developers

Of particular interest in understanding the code is the __server.poc.RadiusListener__ class, the __server.poc.Flows__ class, and the
__server.poc.Transition__ class. The state machine is constructed in the RadiusListener's main method and is fairly comprehensible
based upon the class names and methods used for construction. These classes were only to enable the POC and most likely
will be replaced with some other mechanism as we roll into openAM the ability to configure different radius clients and
the authentication conversation flow for each.

Additionally, the three implemented channel services would ostensibly be replaced by selected openAM authentication modules.
This was only a POC and can be adjusted as vision and direction dictates.


# Questions?

If you have questions send them to Mark Boyd
at boydmr@ldschurch.org.

