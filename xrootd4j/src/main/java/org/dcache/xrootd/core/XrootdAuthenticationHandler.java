/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.core;

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
import org.dcache.xrootd.plugins.ProxyDelegationClient;
import org.dcache.xrootd.plugins.authn.none.NoAuthenticationHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.LoginResponse;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.RequiresTLS;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.util.UserNameUtils;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.TLSSessionInfo.isTLSOn;

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
    private final ProxyDelegationClient _proxyDelegationClient;
    private       TLSSessionInfo        _tlsSessionInfo;
    private       SigningPolicy         _signingPolicy;

    private AuthenticationHandler _authenticationHandler;

    private enum State { NO_LOGIN, NO_AUTH, AUTH }
    private volatile State _state = State.NO_LOGIN;

    private XrootdSession _session;

    public XrootdAuthenticationHandler(AuthenticationFactory authenticationFactory,
                                       ProxyDelegationClient proxyDelegationClient)
    {
        _authenticationFactory = authenticationFactory;
        _proxyDelegationClient = proxyDelegationClient;
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
                            LoginRequest loginRequest = (LoginRequest) request;
                            loginRequest.setUserName(UserNameUtils.checkUsernameValid(loginRequest.getUserName()));
                            _session = new XrootdSession(_sessionId, ctx.channel(), loginRequest);
                            request.setSession(_session);
                            doOnLogin(ctx, loginRequest);
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
                request.setSession(_session);
                if (_tlsSessionInfo != null && _tlsSessionInfo.serverUsesTls()) {
                    boolean isStarted = _tlsSessionInfo.serverTransitionedToTLS(kXR_bind, ctx);
                    _log.debug("kXR_bind, server has now transitioned to tls? {}.", isStarted);
                }
                super.channelRead(ctx, msg);
                break;
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
                new ErrorResponse<>(request, e.getError(), e.getMessage());
            ctx.writeAndFlush(error);
        } catch (RuntimeException e) {
            _log.error("xrootd server error while processing " + msg
                                       + " (please report this to support@dcache.org)", e);
            ErrorResponse error =
                new ErrorResponse<>(request, kXR_ServerError,
                                    String.format("Internal server error (%s)",
                                                  e.getMessage()));
            ctx.writeAndFlush(error);
        }
    }

    public ProxyDelegationClient getCredentialStoreClient()
    {
        return _proxyDelegationClient;
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx)
    {
        if (_proxyDelegationClient != null) {
            _proxyDelegationClient.close();
        }
    }

    public void setSigningPolicy(SigningPolicy signingPolicy)
    {
        _signingPolicy = signingPolicy;
    }

    public void setTlsSessionInfo(TLSSessionInfo tlsSessionInfo)
    {
        _tlsSessionInfo = tlsSessionInfo;
    }

    /**
     * Called at the end of successful login/authentication.
     *
     * Subclasses may override this method to add additional
     * processing and internal mapping of the Subject.
     *
     * If the subclass throws XrootdException then the login is
     * aborted.
     *
     * @param context the Netty context
     * @param subject the subject that logged in
     */
    protected Subject login(ChannelHandlerContext context, Subject subject)
                    throws XrootdException
    {
        return subject;
    }

    private void doOnLogin(ChannelHandlerContext context,
                           LoginRequest request)
        throws XrootdException
    {
        try {
            _authenticationHandler
                            = _authenticationFactory.createHandler(_proxyDelegationClient);

            /*
             *  check to see if we need TLS at login.
             */
            if (_authenticationHandler instanceof RequiresTLS
                            && !isTLSOn(context)) {
                throw new XrootdException(kXR_Unsupported, "TLS is required "
                                + "for " + _authenticationHandler.getProtocol());
            }

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
        if (_tlsSessionInfo != null && _tlsSessionInfo.serverUsesTls()) {
            boolean isStarted = _tlsSessionInfo.serverTransitionedToTLS(kXR_auth,
                                                                         context);
            _log.debug("kXR_auth, server has now transitioned to tls? {}.",
                       isStarted);
        } else if (!(_authenticationHandler instanceof NoAuthenticationHandler)
                        && !isTLSOn(context)
                        && _signingPolicy.isSigningOn()) {
            /*
             * Add the sigver decoder to the pipeline and remove the original
             * message decoder.
             *
             * We only do this if we are in fact enforcing a protocol;
             * hence the check that the handler is not the NOP placeholder.
             */
            BufferDecrypter decrypter = _authenticationHandler.getDecrypter();
            context.pipeline().addAfter("decoder",
                                         "sigverDecoder",
                                         new XrootdSigverDecoder(_signingPolicy,
                                                                 decrypter));
            context.pipeline().remove("decoder");
            _log.debug("switched decoder to sigverDecoder, decrypter {}.", decrypter);
        }

        _authenticationHandler = null;
    }
}
