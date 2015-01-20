/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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

import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.InvalidHandlerConfigurationException;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.LoginResponse;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * Netty handler implementing Xrootd kXR_login, kXR_auth, and kXR_endsess.
 *
 * Delegates the authentication steps to an AuthenticationHandler. Rejects
 * all other messages until login has completed.
 *
 * Note the difference between this class and AuthenticationHandler. The
 * latter is part of a plugin implementing the core authentication logic
 * whereas this class is a Netty handler.
 *
 * The class may be subclassed to override the <code>authenticated</code> method
 * to add additional operations after authentication.
 */
public class XrootdAuthenticationHandler extends ChannelInboundHandlerAdapter
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdAuthenticationHandler.class);

    private static final ConcurrentMap<XrootdSessionIdentifier,XrootdSession> _sessions =
        Maps.newConcurrentMap();

    private final AtomicBoolean _isInProgress = new AtomicBoolean(false);
    private final XrootdSessionIdentifier _sessionId = new XrootdSessionIdentifier();

    private final AuthenticationFactory _authenticationFactory;
    private AuthenticationHandler _authenticationHandler;

    private enum State { NO_LOGIN, NO_AUTH, AUTH }
    private volatile State _state = State.NO_LOGIN;

    private XrootdSession _session;

    public XrootdAuthenticationHandler(AuthenticationFactory authenticationFactory)
    {
        _authenticationFactory = authenticationFactory;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception
    {
        _sessions.remove(_sessionId);
        super.channelInactive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception
    {
        /* Pass along any message that is not an xrootd requests.
         */
        if (!(msg instanceof XrootdRequest)) {
            super.channelRead(ctx, msg);
            return;
        }

        XrootdRequest request = (XrootdRequest) msg;
        int reqId = request.getRequestId();

        try {
            switch (reqId) {
            case kXR_login:
                try {
                    if (_isInProgress.compareAndSet(false, true)) {
                        try {
                            _state = State.NO_LOGIN;
                            _session = new XrootdSession(_sessionId, ctx.channel(), (LoginRequest) request);
                            request.setSession(_session);
                            doOnLogin(ctx, (LoginRequest) request);
                            _sessions.put(_sessionId, _session);
                        } finally {
                            _isInProgress.set(false);
                        }
                    } else {
                        throw new XrootdException(kXR_inProgress, "Login in progress");
                    }
                } finally {
                    ReferenceCountUtil.release(request);
                }
                break;
            case kXR_auth:
                try {
                    if (_isInProgress.compareAndSet(false, true)) {
                        try {
                            switch (_state) {
                            case NO_LOGIN:
                                throw new XrootdException(kXR_NotAuthorized, "Login required");
                            case AUTH:
                                throw new XrootdException(kXR_InvalidRequest, "Already authenticated");
                            }
                            request.setSession(_session);
                            doOnAuthentication(ctx, (AuthenticationRequest) request);
                        } finally {
                            _isInProgress.set(false);
                        }
                    } else {
                        throw new XrootdException(kXR_inProgress, "Login in progress");
                    }
                } finally {
                    ReferenceCountUtil.release(request);
                }
                break;
            case kXR_endsess:
                try {
                    switch (_state) {
                    case NO_LOGIN:
                        throw new XrootdException(kXR_NotAuthorized, "Login required");
                    case NO_AUTH:
                        throw new XrootdException(kXR_NotAuthorized, "Authentication required");
                    }
                    request.setSession(_session);
                    doOnEndSession(ctx, (EndSessionRequest) request);
                } finally {
                    ReferenceCountUtil.release(request);
                }
                break;

            case kXR_bind:
            case kXR_protocol:
                request.setSession(_session);
                super.channelRead(ctx, msg);
                break;
            case kXR_ping:
                if (_state == State.NO_LOGIN) {
                    ReferenceCountUtil.release(request);
                    throw new XrootdException(kXR_NotAuthorized, "Login required");
                }
                request.setSession(_session);
                super.channelRead(ctx, msg);
                break;
            default:
                switch (_state) {
                case NO_LOGIN:
                    ReferenceCountUtil.release(request);
                    throw new XrootdException(kXR_NotAuthorized, "Login required");
                case NO_AUTH:
                    ReferenceCountUtil.release(request);
                    throw new XrootdException(kXR_NotAuthorized, "Authentication required");
                }
                request.setSession(_session);
                super.channelRead(ctx, msg);
                break;
            }
        } catch (XrootdException e) {
            ErrorResponse error =
                new ErrorResponse<>(request, e.getError(), Strings.nullToEmpty(e.getMessage()));
            ctx.writeAndFlush(error);
        } catch (RuntimeException e) {
            _log.error("xrootd server error while processing " + msg + " (please report this to support@dcache.org)", e);
            ErrorResponse error =
                new ErrorResponse<>(request, kXR_ServerError,
                                    String.format("Internal server error (%s)", e.getMessage()));
            ctx.writeAndFlush(error);
        }
    }

    private void doOnLogin(ChannelHandlerContext context,
                           LoginRequest request)
        throws XrootdException
    {
        try {
            _authenticationHandler = _authenticationFactory.createHandler();

            LoginResponse response =
                new LoginResponse(request, _sessionId,
                                  _authenticationHandler.getProtocol());

            if (_authenticationHandler.isCompleted()) {
                authenticated(context, _authenticationHandler.getSubject());
            } else {
                _state = State.NO_AUTH;
            }

            context.writeAndFlush(response);
        } catch (InvalidHandlerConfigurationException e) {
            _log.error("Could not instantiate authentication handler: {}", e);
            throw new XrootdException(kXR_ServerError, "Internal server error");
        }
    }

    private void doOnAuthentication(ChannelHandlerContext context,
                                    AuthenticationRequest request)
        throws XrootdException
    {
        XrootdResponse<AuthenticationRequest> response =
            _authenticationHandler.authenticate(request);
        if (_authenticationHandler.isCompleted()) {
            /* If a subclass rejects the authenticated subject then
             * the authentication status is reset.
             */
            _state = State.NO_LOGIN;
            authenticated(context, _authenticationHandler.getSubject());
        }
        context.writeAndFlush(response);
    }

    private void doOnEndSession(ChannelHandlerContext ctx, EndSessionRequest request)
        throws XrootdException
    {
        XrootdSession session = _sessions.get(request.getSessionId());
        if (session == null) {
            throw new XrootdException(kXR_NotFound, "session not found");
        }
        if (!session.hasOwner(_session.getSubject())) {
            throw new XrootdException(kXR_NotAuthorized, "not session owner");
        }
        session.getChannel().close();
        ctx.writeAndFlush(new OkResponse<>(request));
    }

    private void authenticated(ChannelHandlerContext context, Subject subject)
        throws XrootdException
    {
        _session.setSubject(login(context, subject));
        _state = State.AUTH;
        _authenticationHandler = null;
    }

    /**
     * Called at the end of successful login/authentication.
     *
     * Subclasses may override this method to add additional
     * processing and internal mapping of the Subject.
     *
     * If the subclass throws XrootdException then the login is
     * aborted.
     */
    protected Subject login(ChannelHandlerContext context, Subject subject)
        throws XrootdException
    {
        return subject;
    }
}
