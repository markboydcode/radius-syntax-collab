package com.sun.identity.authentication.modules.radius.server.spi.handlers;

import com.sun.identity.authentication.AuthContext;
import com.sun.identity.authentication.modules.radius.client.*;
import com.sun.identity.authentication.modules.radius.server.RadiusResponseHandler;
import com.sun.identity.authentication.modules.radius.server.spi.AccessRequestHandler;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.HttpCallback;
import com.sun.identity.authentication.spi.PagePropertiesCallback;
import com.sun.identity.authentication.spi.RedirectCallback;

import javax.security.auth.callback.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This RADIUS handler authenticates against an authentication chain and realm specified via configuration. It uses
 * OpenAM's AuthContext object. This flow is as follows. It is also important to note that challenge answers are passed
 * in the RADIUS packet via the password field as per spec.
 *
 * <pre>
 *
 * RADIUS CLIENT                            OPENAM
 *      |                                      .
 *      | AccessRequest                        .
 *      | [username + password]                .
 *      + -----------------------------------> +
 *      .                                      | ac = new AuthContext(realm)
 *      .                                      | ac.login()
 *      .                                      |
 *      .   at a minimum the auth chain used   | ac.hasMoreRequirements()
 *      .   must have a first module that      | callback[] cbs = ac.getRequirements(true)
 *      .   accepts username and password -->  | find nameCallback and inject username
 *      .                                      | find passwordCallback and inject password
 *      . AccessReject                         |
 *      + <----------------------------------- + if unable to find name/password callbacks or inject values
 *      .                                      |
 *      .                                      +-- while ac.hasMoreRequirements()
 *      .                                      .    | callback[] cbs = ac.getRequirements(true)
 *      .                                      .    |
 *      .                                      .    +-- for n=0 to cbs.length-1 for each cbs that accepts user input
 *      .                                      .    .    | issue challenge, gather response, and inject into the callback
 *      . AccessChallenge                      .    .    |
 *      . [message + state(n)]                 .    .    |
 *      + <--------------------------------------------- +
 *      |                                      .    .    .
 *      | AccessRequest                        .    .    .
 *      | [username + answer + state(n)]       .    .    .
 *      + ---------------------------------------------> +
 *      .                                      .    .    | inject value into cbs(n)
 *      .                                      .    +----+
 *      .                                      .    |
 *      .                                      .    | ac.submit(cbs)
 *      .                                      +----+
 *      .                                      |
 *      . AccessAccept                         | s = ac.getStatus()
 *      + <----------------------------------- + if s == SUCCESS
 |      .                                      |
 *      . AccessReject                         |
 *      + <----------------------------------- + all else
 *      |                                      .
 *      |                                      .
 * </pre>
 *
 * Created by markboyd on 11/26/14.
 */
public class OpenAMAuthHandler implements AccessRequestHandler {
    private static final Logger cLog = Logger.getLogger(OpenAMAuthHandler.class.getName());

    /**
     * Holds the ContextHolder instances between calls from clients. ContextHolder includes the OpenAM AuthContext
     * object that keeps track of where the user is in the process of authenticating.
     */
    private static final Map<String, ContextHolder> contextCache = new HashMap<String, ContextHolder>();

    /**
     * Generator of our cache keys.
     */
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * The key in the config map whose value holds the name of the realm to which we should authenticate users.
     */
    private static final java.lang.String REALM = "realm";

    /**
     * The key in the config map whose value holds the name of the authentication chain in the specified realm that
     * should be used for authenticating users.
     */
    private static final java.lang.String AUTH_CHAIN = "chain";

    /**
     * The default delay between scans of the cache to purge expired holders.
     */
    private static final int DEFAULT_CACHE_SWEEP_DELAY_SECONDS = 60;

    /**
     * Thread responsible for scanning cache for expired holders and removing them.
     */
    private static Thread SWEEPER = loadCacheSweeper();

    /**
     * Our ShutdownListener instance to terminate our sweeper thread at shutdown time.
     */
    private static ShutdownListener shutdownListener = new ShutdownListener() {
        @Override
        public void terminate() {
            Thread t = OpenAMAuthHandler.SWEEPER;
            String name = t.getName();

            if (t != null) {
                t.interrupt();

                while (OpenAMAuthHandler.SWEEPER != null) {
                    cLog.log(Level.INFO, "Waiting for " +  name + " to exit.");
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                    }
                }
            }
        }
    };

    /**
     * Loads the cache sweeper thread for removing expired holders.
     *
     * @return
     */
    private static Thread loadCacheSweeper() {
        Thread t = new Thread(new CacheSweeper());
        t.setName(OpenAMAuthHandler.class.getSimpleName() + "-" + CacheSweeper.class.getSimpleName());
        t.setDaemon(true);
        t.start();
        return t;
    }

    /**
     * The cache sweeper that removes expired holders.
     */
    private static class CacheSweeper implements Runnable {

        @Override
        public void run() {
            cLog.log(Level.INFO, Thread.currentThread().getName() + " thread started.");
            boolean notInterrupted = true;
            int sweepDelay = DEFAULT_CACHE_SWEEP_DELAY_SECONDS;

            while (notInterrupted) {
                try {
                    Thread.sleep(sweepDelay);
                } catch (InterruptedException e) {
                    notInterrupted = false;
                    continue;
                }
                long now = System.currentTimeMillis();
                int purgedItems = 0;

                // now scan cache for expired holders
                synchronized (contextCache) {
                    for(Iterator<Map.Entry<String, ContextHolder>> itr = contextCache.entrySet().iterator(); itr.hasNext(); ) {
                        Map.Entry<String, ContextHolder> ent = itr.next();

                        if (ent.getValue().millisExpiryPoint < now) {
                            itr.remove();
                            purgedItems++;
                        }
                    }
                }
                if (purgedItems > 0) {
                    cLog.log(Level.INFO, "Purged " + purgedItems + " items from " + OpenAMAuthHandler.class.getSimpleName()
                    + " cache.");
                }
            }
            cLog.log(Level.SEVERE, "Thread " + Thread.currentThread().getName() + " interrupted. Exiting.");
            SWEEPER = null;
        }
    }

    /**
     * The realm containing the authentication chain through which we will be authenticating.
     */
    private String realm = null;

    /**
     * The authentication chain through which we will be authenticating.
     */
    private String authChain = null;


    /**
     * Returns the number of items currently in the cache which reflects the number of authN attempts in-process. This
     * could include aborted attempts that haven't timed out.
     * @return
     */
    public static final int getInProcessAuthenticationCount() {
        return contextCache.size();
    }

    @Override
    public void init(Properties config) {
        realm = getConfigProperty(REALM, config, true);
        authChain = getConfigProperty(AUTH_CHAIN, config, true);
    }

    /**
     * Gets the specified property or throws an IllegalStateException if the property is not found or is empty.
     * @return
     */
    private static String getConfigProperty(String propName, Properties config, boolean required) {
        String value = config.getProperty(propName);

        if (required && (value == null || "".equals(value))) {
            throw new IllegalStateException("Configuration property '" + propName + "' not found in handler configuration. " +
                    "It must be added to the Configuration Properties for this class in the Radius Client's configuration.");
        }
        return value;
    }

    /**
     * Handles the request in potentially two distinct ways depending on whether a state attribute is found in the
     * request or not. When no state field is found this is an initial request starting the authentication process
     * and the request will have username and password embedded and ready for consumption by the first module in the
     * chain. Any request with a state attribute is a user response to a previous challenge response that we sent
     * back to them in a previously started authentication process. The number of challenge responses that are sent
     * and their corresponding replies is dependent upon the number of modules in the chain and the number of callback
     * fields in each set of callbacks. A set of callbacks represents one grouping of data needed by a module to
     * complete its next step in the authentication process that it implements. This grouping in a web environment
     * constitutes a single page into which a number of fields can receive data. However, to gather additional feedback
     * from a user the radius protocol only supports a challenge response with a text message and state and radius
     * clients typically present that message and a single text input field with a label like, "Answer", and submit
     * and cancel buttons. This means that we only get a single answer per radius challenge response. Therefore, for
     * some callback groupings we will need to return multiple challenge responses before we can submit the callback
     * set's user response values back to the module to take the next step in authentication.
     *
     * @param request
     * @param respHandler
     */
    @Override
    public void handle(AccessRequest request, RadiusResponseHandler respHandler) {
        Map<Class, Attribute> reqAttsMap = loadAttsMap(request);
        StateAttribute state = (StateAttribute) reqAttsMap.get(StateAttribute.class);
        ContextHolder holder = null;

        if (state != null) {
            String cacheKey = state.getString();
            holder = contextCache.get(cacheKey);
        }
        // always get password attribute regardless of whether starting or returning more input since user input is
        // always sent via the password field.
        UserPasswordAttribute credAtt = (UserPasswordAttribute) reqAttsMap.get(UserPasswordAttribute.class);
        String credential = null;

        try {
            credential = respHandler.extractPassword(credAtt);
        } catch (IOException e) {
            cLog.log(Level.SEVERE, "Unable to extract credential field from RADIUS request. Denying Access.", e);
            rejectAccessAndTerminateProcess(respHandler, holder);
            return;
        }

        if (holder == null) {
            //cLog.log(Level.INFO, "--- new auth - call startAuthProcess");
            holder = startAuthProcess(respHandler, reqAttsMap, credential);
            if (holder.authPhase == ContextHolder.AuthPhase.TERMINATED) {
                // oops. something happened and reject message was already sent. so drop out here.
                return;
            }
        }
        //cLog.log(Level.INFO, "--- call gatherUserInput");
        gatherUserInput(respHandler, holder, credential, state);

        if (holder.authPhase == ContextHolder.AuthPhase.FINALIZING) {
            //cLog.log(Level.INFO, "--- call finalizeAuthProcess");
            finalizeAuthProcess(respHandler, holder);
        }
    }

    /**
     * Returns our shutdown listener instance.
     *
     * @return
     */
    @Override
    public ShutdownListener getShutdownListener() {
        return shutdownListener;
    }

    /**
     * Evaluates if they successfully authenticated or failed and sends an AccessAllow or AccessReject accordingly.
     *
     * @param respHandler
     * @param holder
     */
    private void finalizeAuthProcess(RadiusResponseHandler respHandler, ContextHolder holder) {
        AuthContext.Status status = holder.authContext.getStatus();
        //cLog.log(Level.INFO, "--- ac.getStatus() = " + status);

        if (status == AuthContext.Status.SUCCESS) {
            // they made it. Let them in.
            //cLog.log(Level.INFO, "Successfully authenticated. Granting Access.");
            allowAccessAndTerminateProcess(respHandler, holder);
            return;
        }
        // else, deny access
        //cLog.log(Level.INFO, "Failed authentication. Denying Access.");
        rejectAccessAndTerminateProcess(respHandler, holder);
    }

    private void gatherUserInput(RadiusResponseHandler respHandler, ContextHolder holder, String answer, StateAttribute state) {
        // we have a while loop here because there are callback sets that are empty of input callbacks and contain
        // only a properties callback. Those callback sets must simply be submitted without any input being injected
        // allowing the auth process to move to the next set. The while loop allows us to flow through without issuing
        // a challenge response, get the next set loaded, and then start sending a challenges for that set.
        while (holder.authPhase == ContextHolder.AuthPhase.GATHERING_INPUT) {
            if (holder.callbacks == null) {
                //cLog.log(Level.INFO, "--- callbacks == null in gatherUserInput");
                // either just starting process or just finished submitting a set of callback input values
                if (! isNextCallbackSetAvailable(respHandler, holder)) {
                    // no further input from user needed or error occurred
                    if (holder.authPhase == ContextHolder.AuthPhase.TERMINATED) {
                        return;
                    }

                    //cLog.log(Level.INFO, "--- NextCallbackSet not-available in gatherUserInput - move to finalization");
                    holder.authPhase = ContextHolder.AuthPhase.FINALIZING;
                    return;
                }
            }
            else {
                //cLog.log(Level.INFO, "--- callbacks[" + holder.callbacks.length + "] in gatherUserInput - ");
                // we are gathering for current set.
                boolean injected = injectAnswerForCallback(respHandler, holder, answer); // answers always come through the request's password field

                if (! injected) {
                    return; // couldn't inject and already sent reject response so exit out
                }
            }
            // new callbacks available or still gathering input for the current set. if all callbacks have values
            // then submit and loop around again to get next set. else send challenge response to gather input for the
            // next callback
            if (holder.idxOfCurrentCallback > holder.callbacks.length-1) {
//                cLog.log(Level.INFO, "--- holder.idxOfCurrentCallback " + holder.idxOfCurrentCallback
//                        + " > holder.callbacks.length-1 " + (holder.callbacks.length-1)
//                        + " in gatherUserInput - submitting/set callbacks=null");
                try {
                    holder.authContext.submitRequirements(holder.callbacks);
                } catch(Throwable t) {
                    cLog.log(Level.SEVERE, "Exception thrown while submitting callbacks. Rejecting access.", t);
                    rejectAccessAndTerminateProcess(respHandler, holder);
                    return;
                }
                holder.callbacks = null;
            }
            else {
                ReplyMessageAttribute msg = getNextCallbackReplyMsg(respHandler, holder);

                if (msg == null) {
                    return; // failed to inject and already sent a reject msg so stop processing at this point.
                }
                // if we get here then we have a challenge response message ready to send
                AccessChallenge challenge = new AccessChallenge();

                if (state == null) { // as when starting authentication
                    state = new StateAttribute(holder.cacheKey);
                }
                challenge.addAttribute(state);
                challenge.addAttribute(msg);
                respHandler.send(challenge);
                return; // exit out and await response to challenge response
            }
        }
    }

    /**
     * Obtains the next set of callbacks updating our info set or sets the callbacks to null if unable to acquire and
     * update the info set and sends an accessReject response in that case. Returns true if callback set was loaded into
     * holder. Returns false if they couldn't be loaded or were empty which may be a valid state depending on the
     * caller. Sets holder.authPhase = TERMINATED if something happened causing the
     * authentication process to fail.
     *
     *
     * @param context
     * @param holder
     * @return
     */
    private boolean isNextCallbackSetAvailable(RadiusResponseHandler context, ContextHolder holder) {
        boolean moreCallbacksAvailable = holder.authContext.hasMoreRequirements();

        if (!moreCallbacksAvailable) {
//            cLog.log(Level.INFO, "--- no callbacks available, set callbacks=null in isNextCallbackSetAvailable");
            holder.callbacks = null;
            return false;
        }
        holder.callbacks = holder.authContext.getRequirements(true); // true means do NOT filter PagePropertiesCallbacks

        if (holder.callbacks == null) { // should never happen but example online included check
//            cLog.log(Level.INFO, "--- callbacks == null after ac.getReqs() called in isNextCallbackSetAvailable");
            return false;
        }

        // process page properties piece
        if (holder.callbacks[0] instanceof PagePropertiesCallback) { // not a formal callback, openam specific
            PagePropertiesCallback pp = (PagePropertiesCallback) holder.callbacks[0];
            holder.callbackSetProps = pp;
            holder.idxOfCurrentCallback = 1; // since page properties cb is at zero index
            String moduleName = pp.getModuleName();

            if (! moduleName.equals(holder.moduleName)) {
                // entering new module
                holder.moduleName = moduleName;
                holder.chainModuleIndex++;
                holder.idxOfCallbackSetInModule = 0;
//                cLog.log(Level.INFO, "New Module Incurred: " + holder.moduleName + " with callbacks["
//                + holder.callbacks.length + "]");
            }
            else {
                holder.idxOfCallbackSetInModule++;
//                cLog.log(Level.INFO, "New Callback Set[" + holder.callbacks.length + "] Incurred in Module: "
//                        + holder.moduleName);
            }
            // update the
            holder.millisExpiryForCurrentCallbacks = 1000L * pp.getTimeOutValue();
            holder.millisExpiryPoint = System.currentTimeMillis() + holder.millisExpiryForCurrentCallbacks;
        }
        else {
            cLog.log(Level.SEVERE, "Callback at index 0 is not of type PagePropertiesCallback!!!");
            rejectAccessAndTerminateProcess(context, holder);
            return false;
        }

        // now fail fast if we find unsupportable callback types
        boolean httpCbIncurred = false;
        boolean redirectCbIncurred = false;

        for (int i=1; i<holder.callbacks.length; i++) {
            Callback cb = holder.callbacks[i];
            if (cb instanceof HttpCallback) {
                httpCbIncurred = true;
                break;
            }
            else if (cb instanceof RedirectCallback) {
                redirectCbIncurred = true;
                break;
            }
        }
        if (httpCbIncurred || redirectCbIncurred) {
            cLog.log(Level.SEVERE, "Radius can not support "
                    + ( httpCbIncurred ? HttpCallback.class.getSimpleName() : RedirectCallback.class.getSimpleName() )
                    + " used by module " + holder.chainModuleIndex + " with name " + holder.moduleName
                    + " in chain '" + this.authChain + "'. Denying Access.");
            rejectAccessAndTerminateProcess(context, holder);
            return false;
        }
        return true;
    }

    /**
     * Sends a RADIUS AccessReject response and cleans up the cache and authentication context if it not null by calling its
     * logout method.
     *  @param respHandler
     * @param holder
     */
    private void rejectAccessAndTerminateProcess(RadiusResponseHandler respHandler, ContextHolder holder) {
        respHandler.send(new AccessReject());
        terminateAuthnProcess(holder);
    }

    /**
     * Sends RADIUS AccessAccept response and cleans up the cache and authentication context.
     *
     * @param respHandler
     * @param holder
     */
    private void allowAccessAndTerminateProcess(RadiusResponseHandler respHandler, ContextHolder holder) {
        respHandler.send(new AccessAccept());
        terminateAuthnProcess(holder);
    }

    /**
     * Removes the holder from cache, sets the state to terminated, and calls logout() on OpenAM's AuthContextLocal to
     * terminate open am's session since RADIUS only uses open am for authenticating and won't send any further
     * requests related to this access grant.
     *
     * @param holder
     */
    private void terminateAuthnProcess(ContextHolder holder) {
        synchronized (contextCache) {
            contextCache.remove(holder.cacheKey);
        }
        holder.authPhase = ContextHolder.AuthPhase.TERMINATED;

        if (holder.authContext != null && holder.authContext.getStatus() == AuthContext.Status.SUCCESS) {
            try {
                holder.authContext.logout();
            } catch (AuthLoginException e) {
                //cLog.log(Level.INFO, "Unable to logout of AuthContext. Ignoring.", e);
            }
        }
    }

    /**
     * Injects the user's answer into the callback currently waiting for one with proper handling for the type of
     * callback. Increments the index of the current callback and returns true if the value was successly injected
     * or false if it failed and terminated authentication.
     *
     * @param respHandler
     * @param holder
     * @param answer
     */
    private boolean injectAnswerForCallback(RadiusResponseHandler respHandler, ContextHolder holder, String answer) {
        if (holder.callbacks == null) {
            return false;
        }
        Callback cb = holder.callbacks[holder.idxOfCurrentCallback++];

        if (cb instanceof NameCallback) {
            NameCallback nc = (NameCallback) cb;
            ((NameCallback) cb).setName(answer);
            //cLog.log(Level.INFO, "--- set NameCallback=" + answer);
        }
        else if (cb instanceof PasswordCallback) {
            PasswordCallback pc = (PasswordCallback) cb;
            pc.setPassword(answer.toCharArray());
            //cLog.log(Level.INFO, "--- set PasswordCallback=" + answer);
        }
        else if (cb instanceof ChoiceCallback) {
            ChoiceCallback cc = (ChoiceCallback) cb;
            int maxIdx = cc.getChoices().length - 1;

            if ("".equals(answer)) {
                // user didn't provide an answer so accept default
                cc.setSelectedIndex(cc.getDefaultChoice());
                //cLog.log(Level.INFO, "--- set ChoiceCallback=default(" + cc.getDefaultChoice() + ")");
                return true;
            }
            boolean answerContainsSeparator = answer.indexOf(' ') != -1;
            if (cc.allowMultipleSelections() && answerContainsSeparator) {
                // may need to parse answer
                if (answerContainsSeparator) {
                    String[] answers = answer.split(" ");
                    List<Integer> idxs = new ArrayList<Integer>();

                    for (String ans : answers) {
                        if (! "".equals(ans)) {
                            int idx = parseInt(ans, answer, maxIdx, holder, cb, respHandler);
                            if (idx == -1) {
                                // failed parsing and sent reject message so return.
                                //cLog.log(Level.INFO, "--- ChoiceCallback failed parsing mult");
                                return false;
                            }
                            idxs.add(idx);
                        }
                    }
                    int[] selected = new int[idxs.size()];
                    for(int i=0; i<selected.length; i++) {
                        selected[i] = idxs.get(i);
                    }
                    cc.setSelectedIndexes(selected);
                    //cLog.log(Level.INFO, "--- set ChoiceCallback=" + Arrays.asList(selected));

                }
            }
            else {
                int idx = parseInt(answer, answer, maxIdx, holder, cb, respHandler);
                if (idx == -1) {
                    // failed parsing and send reject message so return.
                    //cLog.log(Level.INFO, "--- ChoiceCallback failed parsing");
                    return false;
                }
                cc.setSelectedIndex(idx);
                //cLog.log(Level.INFO, "--- set ChoiceCallback=" + idx);
            }
        }
        else if (cb instanceof ConfirmationCallback) {
            ConfirmationCallback cc = (ConfirmationCallback) cb;
            int maxIdx = cc.getOptions().length - 1;

            if ("".equals(answer)) {
                // user didn't provide an answer so accept default
                cc.setSelectedIndex(cc.getDefaultOption());
                //cLog.log(Level.INFO, "--- set ConfirmationCallback=default(" + cc.getDefaultOption() + ")");
                return true;
            }
            int idx = parseInt(answer, answer, maxIdx, holder, cb, respHandler);
            if (idx == -1) {
                // failed parsing and send reject message so return.
                //cLog.log(Level.INFO, "--- ConfirmationCallback failed parsing");
                return false;
            }
            cc.setSelectedIndex(idx);
            //cLog.log(Level.INFO, "--- set ConfirmationCallback=" + idx);
        }
        else {
            cLog.log(Level.SEVERE, "Unrecognized callback type '" + cb.getClass().getSimpleName()
                    + "' while processing challenge response. Unable to submit answer. Denying Access.");
            rejectAccessAndTerminateProcess(respHandler, holder);
            return false;
        }
        // reset the timeout since we just received confirmation that the user is still there.
        holder.millisExpiryPoint = System.currentTimeMillis() + holder.millisExpiryForCurrentCallbacks;
        return true;
    }

    /**
     * Parses the String intVal as an integer returning that value or returning a -1 indicating that parsing failed
     * terminating authentication, logging a suitable message, and sending the access reject response if the string
     * is not a valid number or is out of range.
     *
     * @param intVal
     * @param answer
     * @param maxIdx
     * @param holder
     * @param cb
     * @param respHandler
     * @return
     * */
    private int parseInt(String intVal, String answer, int maxIdx, ContextHolder holder, Callback cb, RadiusResponseHandler respHandler) {
        int idx = -1;
        try {
            idx = Integer.parseInt(intVal);
        }
        catch(NumberFormatException e) {
            cLog.log(Level.SEVERE, "Invalid number '" + intVal + "' specified in answer '"
                    + answer + "' for callback " + holder.idxOfCurrentCallback + " of type "
                    + cb.getClass().getSimpleName() + " for callback set " + holder.idxOfCallbackSetInModule + " in module "
                    + holder.chainModuleIndex + (holder.moduleName != null ? " with name " + holder.moduleName : "" )
                    + " of authentication chain " + authChain + " in realm " + realm + ". Denying Access.");
            rejectAccessAndTerminateProcess(respHandler, holder);
            return idx;
        }
        if (idx < 0 || idx > maxIdx) {
            cLog.log(Level.SEVERE, "Out of range index specified in answer '"
                    + answer + "' for callback " + holder.idxOfCurrentCallback + " of type "
                    + cb.getClass().getSimpleName() + " for callback set " + holder.idxOfCallbackSetInModule + " in module "
                    + holder.chainModuleIndex + (holder.moduleName != null ? " with name " + holder.moduleName : "" )
                    + " of authentication chain " + authChain + " in realm " + realm + ". Must be from 0 to "
                    + maxIdx + ". Denying Access.");
            rejectAccessAndTerminateProcess(respHandler, holder);
            return -1;
        }
        return idx;
    }

    /**
     * Starts the authentication process by creating a new AuthContextLocale and the submitted username and password
     * and passing those to the first module in the authentication chain and completing authentication if that is the
     * only module in the chain or crafting a suitable challenge response to start gathering values for the next
     * module's callbacks. Returns true if authentication was started and user requirements beyond usernamd and password
     * can now be solicited or false if starting failed and a reject message has already been generated.
     *
     *  @param respHandler
     * @param reqAttsMap
     * @param credential
     */
    private ContextHolder startAuthProcess(RadiusResponseHandler respHandler, Map<Class, Attribute> reqAttsMap, String credential) {
        ContextHolder holder = newContextHolder();

        // starting a fresh authentication attempt. That means username and password were passed along.
        UserNameAttribute usrAtt = (UserNameAttribute) reqAttsMap.get(UserNameAttribute.class);

        // now create an authContext and trigger loading of whatever authN modules will be used
        try {
            holder.authContext = new AuthContext(realm);
        } catch (AuthLoginException e) {
            cLog.log(Level.SEVERE, "Unable to start create " + AuthContext.class.getName() + ". Denying Access.", e);
            rejectAccessAndTerminateProcess(respHandler, holder);
            return holder;
        }

        try {
            holder.authContext.login(AuthContext.IndexType.SERVICE, authChain);
        } catch (AuthLoginException e) {
            cLog.log(Level.SEVERE, "Unable to start login process. Denying Access.", e);
            rejectAccessAndTerminateProcess(respHandler, holder);
            return holder;
        }

        if (! isNextCallbackSetAvailable(respHandler, holder)) {
            // couldn't get the callbacks or failure occurred. If failure didn't occur then we need to fail out here
            // since we must have callbacks when starting up the authn process to handle username and password.
            if (holder.authPhase != ContextHolder.AuthPhase.TERMINATED) {
                cLog.log(Level.SEVERE, "Unable to start login process. No callbacks available. Denying Access.");
                rejectAccessAndTerminateProcess(respHandler, holder);
            }
            return holder;
        }

        // for RADIUS we have username and password within the initial request. Therefore, the first module in the
        // chain must support a name and password callback. so walk the set of callbacks representing the first
        // module and inject and then test for further module requirements. if any exist then we must craft a
        // suitable challenge response and await the next request that gets submitted after the radius client has
        // gathered those values.
        boolean injectedUsr = false;
        boolean injectedPwd = false;

        for (int i=holder.idxOfCurrentCallback; i<holder.callbacks.length; i++) {
            if (holder.callbacks[i] instanceof NameCallback) {
                holder.idxOfCurrentCallback++;
                NameCallback nm = (NameCallback) holder.callbacks[i];
                nm.setName(usrAtt.getName());
                injectedUsr = true;
            }
            else if (holder.callbacks[i] instanceof PasswordCallback) {
                holder.idxOfCurrentCallback++;
                PasswordCallback pc = (PasswordCallback) holder.callbacks[i];
                pc.setPassword(credential.toCharArray());
                injectedPwd = true;
            }
            else {
                holder.idxOfCurrentCallback++;
            }
        }
        // did we have NameCallback and PasswordCallback to inject the username and password?
        if (injectedUsr && injectedPwd) {
            holder.authContext.submitRequirements(holder.callbacks);
            //cLog.log(Level.INFO, "--- submitting usr/pwd in startAuthProcess, set callbacks=null");
            holder.callbacks = null; // triggers loading of next set and conveys to gatherer that we have just started
        }
        else {
            // if we get here and didn't submit, then the callbacks array representing the requirements of the first
            // module in the chain didn't support username and password. So log the error and reject access.
            String msg = "First callback set for first module"
            + (holder.moduleName != null ? " '" + holder.moduleName + "'" : "" ) + " in authentication chain '"
                    + this.authChain + "' does not support Username and Password callbacks. Denying Access.";
            cLog.log(Level.SEVERE, msg);
            rejectAccessAndTerminateProcess(respHandler, holder);
        }
        // if we get here then we successfully started the authN process
        holder.authPhase = ContextHolder.AuthPhase.GATHERING_INPUT;
        return holder;
    }

    /**
     * Creates a new ContextHolder and associated unique cache key, injects the holder into the cache, and returns
     * the holder.
     *
     * @return
     */
    private ContextHolder newContextHolder() {
        synchronized (contextCache) {
            while(true) {
                String key =Integer.toHexString(secureRandom.nextInt());
                if (!contextCache.containsKey(key)) {
                    ContextHolder holder = new ContextHolder(key);
                    contextCache.put(holder.cacheKey, holder);
                    return  holder;
                }
            }
        }
    }

    /**
     * Generates reply message for the current callback to be embedded in a challenge response to gather an answer for
     * that callback. If an unknown/unexpected callback type is incurred the process is terminated with a reject
     * response.
     *
     * @param respHandler
     * @param holder
     * @return
     */
    private ReplyMessageAttribute getNextCallbackReplyMsg(RadiusResponseHandler respHandler, ContextHolder holder) {
        ReplyMessageAttribute msg = null;
        Callback cb = holder.callbacks[holder.idxOfCurrentCallback];
        String header = (holder.callbackSetProps != null && ! "".equals(holder.callbackSetProps.getHeader()) ?
                holder.callbackSetProps.getHeader() + " " : "");

        if (cb instanceof NameCallback) {
            msg = new ReplyMessageAttribute(header + ((NameCallback) cb).getPrompt());
        }
        else if (cb instanceof PasswordCallback) {
            msg = new ReplyMessageAttribute(header + ((PasswordCallback) cb).getPrompt());
        }
        else if (cb instanceof ChoiceCallback) {
            ChoiceCallback cc = (ChoiceCallback) cb;
            StringBuilder sb = new StringBuilder();
            sb.append(header);
            sb.append(cc.getPrompt());
            if (cc.allowMultipleSelections()) {
                // ugh. we'll have to figure out how to translate this suitably in view of sentence structure for
                // a given locale.
                sb.append(" (Separate Selected Numbers by Spaces"); // TODO: LOCALIZE
                if (cc.getDefaultChoice() >= 0) {
                    sb.append(". Default is " + cc.getDefaultChoice());
                }
                sb.append(".)");
            }
            sb.append('\n');
            String[] choices = cc.getChoices();

            for(int j=0; j<choices.length; j++) {
                String choice = choices[j];
                if (j!=0) {
                    sb.append(",\n");
                }
                sb.append(j);
                sb.append(" = ");
                sb.append(choice);
            }
            msg = new ReplyMessageAttribute(sb.toString());
        }
        else if (cb instanceof ConfirmationCallback) {
            ConfirmationCallback cc = (ConfirmationCallback) cb;
            StringBuilder sb = new StringBuilder();
            sb.append(header);
            sb.append(cc.getPrompt());
            if (cc.getDefaultOption() >= 0) {
                // ugh. ditto on above translation concern
                sb.append(" (Default is ");
                sb.append(cc.getDefaultOption());
                sb.append(".)");
            }
            sb.append('\n');
            String[] options = cc.getOptions();

            for(int j=0; j<options.length; j++) {
                String option = options[j];
                if (j!=0) {
                    sb.append(",\n");
                }
                sb.append(j);
                sb.append(" = ");
                sb.append(option);
            }
            msg = new ReplyMessageAttribute(sb.toString());
        }
        else {  // unknown and unexpected type
            cLog.log(Level.SEVERE, "Radius can not support " + cb.getClass().getSimpleName()
                    + " used by module " + holder.chainModuleIndex + " with name " + holder.moduleName
                    + " in chain '" + this.authChain + "'. Denying Access.");
            rejectAccessAndTerminateProcess(respHandler, holder);
        }
        return msg;
    }

    private Map<Class, Attribute> loadAttsMap(AccessRequest request) {
        Map<Class, Attribute> map = new HashMap<Class, Attribute>();
        AttributeSet atts = request.getAttributeSet();

        for (int i=0; i<atts.size(); i++) {
            Attribute att = atts.getAttributeAt(i);
            // warning: this is lossy for atts that support duplicates like proxyState. but we aren't using those
            // for authentication but only need State, UserName, and UserPassword. So we are good.
            map.put(att.getClass(), att);
        }

        return map;
    }
}
