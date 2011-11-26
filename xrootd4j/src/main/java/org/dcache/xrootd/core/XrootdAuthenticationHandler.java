/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.core;

import javax.security.auth.Subject;
import java.security.SecureRandom;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import static org.jboss.netty.channel.Channels.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.InvalidHandlerConfigurationException;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.LoginResponse;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * Netty handler implementing Xrootd kXR_login and kXR_auth.
 *
 * Delegates the authentication steps to an
 * AuthenticationHandler. Rejects all other messages until login has
 * completed.
 *
 * Note the difference between this class and
 * AuthenticationHandler. The latter is part of a plugin implementing
 * the core authentication logic whereas this class is a Netty handler.
 *
 * The class may be subclassed to override the
 * <code>authenticated</code> method to add additional operations
 * after authentication.
 */
public class XrootdAuthenticationHandler extends SimpleChannelUpstreamHandler
{
    private final static Logger _log =
        LoggerFactory.getLogger(XrootdAuthenticationHandler.class);

    private static final ImmutableSet<Integer> WITHOUT_LOGIN =
        ImmutableSet.of(kXR_bind, kXR_login, kXR_protocol);
    private static final ImmutableSet<Integer> WITHOUT_AUTH =
        ImmutableSet.of(kXR_auth, kXR_bind, kXR_login, kXR_ping, kXR_protocol);

    private static final int SESSION_ID_BYTES = 16;
    private static final SecureRandom _random = new SecureRandom();

    private final AuthenticationFactory _authenticationFactory;
    private AuthenticationHandler _authenticationHandler;

    private enum State { NO_LOGIN, NO_AUTH, AUTH }
    private State _state = State.NO_LOGIN;

    private Subject _subject;
    private final byte[] _session = new byte[SESSION_ID_BYTES];

    public XrootdAuthenticationHandler(AuthenticationFactory authenticationFactory)
    {
        _authenticationFactory = authenticationFactory;
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent event)
    {
        Object msg = event.getMessage();

        /* Pass along any message that is not an xrootd requests.
         */
        if (!(msg instanceof XrootdRequest)) {
            ctx.sendUpstream(event);
            return;
        }

        XrootdRequest request = (XrootdRequest) msg;
        int reqId = request.getRequestId();

        try {
            /* Enforce login and authentication.
             */
            if (_state == State.NO_LOGIN && !WITHOUT_LOGIN.contains(reqId)) {
                throw new XrootdException(kXR_NotAuthorized, "Login required");
            }
            if (_state == State.NO_AUTH && !WITHOUT_AUTH.contains(reqId)) {
                throw new XrootdException(kXR_NotAuthorized, "Authentication required");
            }

            /* Dispatch request.
             */
            switch (reqId) {
            case kXR_login:
                doOnLogin(ctx, event, (LoginRequest) request);
                break;
            case kXR_auth:
                doOnAuthentication(ctx, event, (AuthenticationRequest) request);
                break;
            default:
                request.setSubject(_subject);
                ctx.sendUpstream(event);
                break;
            }
        } catch (XrootdException e) {
            ErrorResponse error =
                new ErrorResponse(request.getStreamId(), e.getError(), e.getMessage());
            event.getChannel().write(error);
        } catch (RuntimeException e) {
            _log.error(String.format("Processing %s failed due to a bug", msg), e);
            ErrorResponse error =
                new ErrorResponse(request.getStreamId(), kXR_ServerError,
                                  String.format("Internal server error (%s)",
                                                e.getMessage()));
            event.getChannel().write(error);
        }
    }

    protected void doOnLogin(ChannelHandlerContext context,
                             MessageEvent event,
                             LoginRequest request)
        throws XrootdException
    {
        try {
            /* Any login request resets the authentication status.
             */
            _state = State.NO_LOGIN;
            _subject = null;

            _random.nextBytes(_session);
            _authenticationHandler =
                _authenticationFactory.createHandler();

            LoginResponse response =
                new LoginResponse(request.getStreamId(), _session,
                                  _authenticationHandler.getProtocol());

            if (_authenticationHandler.isCompleted()) {
                authenticated(context, _authenticationHandler.getSubject());
            } else {
                _state = State.NO_AUTH;
            }

            event.getChannel().write(response);
        } catch (InvalidHandlerConfigurationException e) {
            _log.error("Could not instantiate authentication handler: {}", e);
            throw new XrootdException(kXR_ServerError, "Internal server error");
        }
    }

    protected void doOnAuthentication(ChannelHandlerContext context,
                                      MessageEvent event,
                                      AuthenticationRequest request)
        throws XrootdException
    {
        AbstractResponseMessage response =
            _authenticationHandler.authenticate(request);
        if (_authenticationHandler.isCompleted()) {
            /* If a subclass rejects the authenticated subject then
             * the authentication status is reset.
             */
            _state = State.NO_LOGIN;
            authenticated(context, _authenticationHandler.getSubject());
        }
        event.getChannel().write(response);
    }

    /**
     * Signals the end of authentication.
     *
     * Called at the end of successful login/authentication.
     *
     * Subclasses may override this method to add additional
     * processing. If the subclass throws XrootdException then the
     * login is aborted. Otherwise subclasses must call the superclass
     * version of this method.
     */
    protected void authenticated(ChannelHandlerContext context, Subject subject)
        throws XrootdException
    {
        _state = State.AUTH;
        _subject = subject;
        _authenticationHandler = null;
    }
}
