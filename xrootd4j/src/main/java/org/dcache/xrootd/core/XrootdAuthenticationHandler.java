/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.core;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;

import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;
import javax.security.auth.Subject;
import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.ProxyDelegationClient;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Netty handler implementing Xrootd kXR_auth.
 * <p>
 * Delegates the authentication steps to an AuthenticationHandler. Rejects all other messages until
 * login has completed.
 * <p>
 * Note the difference between this class and AuthenticationHandler. The latter is part of a plugin
 * implementing the core authentication logic whereas this class is a Netty handler.
 * <p>
 * The class may be subclassed to override the <code>authenticated</code> method to add additional
 * operations after authentication.
 */
public class XrootdAuthenticationHandler extends XrootdRequestHandler {

    private static final Logger LOGGER =
          LoggerFactory.getLogger(XrootdAuthenticationHandler.class);

    private final ProxyDelegationClient proxyDelegationClient;
    private final AuthenticationHandler authenticationHandler;

    private XrootdSessionHandler sessionHandler;

    /*
     *  NOTE:  we maintain the now unused first String parameter for backward compatibility.
     */
    public XrootdAuthenticationHandler(String name, AuthenticationFactory authenticationFactory,
          ProxyDelegationClient proxyDelegationClient) {
        this.proxyDelegationClient = proxyDelegationClient;
        authenticationHandler = authenticationFactory.createHandler(proxyDelegationClient);
    }

    public String getProtocol() {
        return authenticationHandler.getProtocolName();
    }

    public AuthenticationHandler getHandler() {
        return authenticationHandler;
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (proxyDelegationClient != null) {
            proxyDelegationClient.close();
        }
    }

    public void setSessionHandler(XrootdSessionHandler sessionHandler) {
        this.sessionHandler = sessionHandler;
    }

    @Override
    protected Object doOnAuthentication(ChannelHandlerContext context,
          AuthenticationRequest request)
          throws XrootdException {
        XrootdResponse<AuthenticationRequest> response = authenticationHandler.authenticate(
              request);
        if (authenticationHandler.isCompleted()) {
            LOGGER.debug("doOnAuthentication, response {}, is completed.", response);
            authenticated(context, authenticationHandler.getSubject());
        }
        return response;
    }

    @Override
    protected Object getResponse(ChannelHandlerContext ctx, XrootdRequest req) {
        switch (req.getRequestId()) {
            case kXR_auth:
                try {
                    return doOnAuthentication(ctx, (AuthenticationRequest) req);
                } catch (XrootdException e) {
                    LOGGER.debug("authenticated, login failed {}: {}.", e.getError(),
                          e.getMessage());
                    sessionHandler.setAuthFailed(ctx);
                    respond(ctx, withError(ctx, req, e.getError(), e.getMessage()));
                    return null;
                } finally {
                    ReferenceCountUtil.release(req);
                }
            default:
                ctx.fireChannelRead(req);
                return null;
        }
    }

    /**
     * Called at the end of successful login/authentication.
     * <p>
     * Subclasses may override this method to add additional processing and internal mapping of the
     * Subject.
     * <p>
     * If the subclass throws XrootdException then the login is aborted.
     *
     * @param context the Netty context
     * @param subject the subject that logged in
     */
    protected Subject login(ChannelHandlerContext context, Subject subject)
          throws XrootdException {
        return subject;
    }

    private void authenticated(ChannelHandlerContext context, Subject subject)
          throws XrootdException {
        sessionHandler.setSubject(login(context, subject));
        sessionHandler.setAuthSucceeded(context);
        LOGGER.debug("authenticated, set subject on session for login.");
    }
}
