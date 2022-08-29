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

import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_NotAuthorized;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Unsupported;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_bind;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_inProgress;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ping;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.security.TLSSessionInfo.isTLSOn;

import com.google.common.collect.Maps;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import javax.security.auth.Subject;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.authn.none.NoAuthenticationHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.LoginResponse;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.RequiresTLS;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.util.UserNameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages kXR_login and the login session.  This handler is responsible for adding the
 * correct authentication handler to the pipeline based on the client protocol interaction.
 */
public class XrootdSessionHandler extends XrootdRequestHandler {

    public static final String SESSION_HANDLER = "sessionHandler";

    private static final Logger LOGGER = LoggerFactory.getLogger(XrootdSessionHandler.class);

    private static final ConcurrentMap<XrootdSessionIdentifier, XrootdSession> SESSIONS =
          Maps.newConcurrentMap();

    private static final XrootdSessionIdentifier CURRENT_SESSION_PLACEHOLDER =
          new XrootdSessionIdentifier(new byte[SESSION_ID_SIZE]);

    private enum State {NO_LOGIN, NO_AUTH, AUTH}

    private final AtomicBoolean inProgress = new AtomicBoolean(false);
    private final XrootdSessionIdentifier sessionId = new XrootdSessionIdentifier();
    private final Map<String, XrootdAuthenticationHandler> handlerMap = new LinkedHashMap<>();

    private XrootdSession session;
    private TLSSessionInfo tlsSessionInfo;
    private SigningPolicy signingPolicy;

    private State state = State.NO_LOGIN;
    private XrootdAuthenticationHandler currentHandler;
    private String currentProtocol;

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        SESSIONS.remove(sessionId);
        super.channelInactive(ctx);
    }

    public void add(XrootdAuthenticationHandler handler) {
        handlerMap.put(handler.getProtocol(), handler);
    }

    public void setSubject(Subject subject) {
        session.setSubject(subject);
    }

    protected Object getResponse(ChannelHandlerContext ctx, XrootdRequest req) throws Exception {
        switch (req.getRequestId()) {
            case kXR_login:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_login");
                return doOnLogin(ctx, (LoginRequest) req);
            case kXR_auth:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_auth");
                if (inProgress.compareAndSet(false, true)) {
                    try {
                        switch (state) {
                            case NO_LOGIN:
                                LOGGER.debug("Request kXR_auth isInProgress: NO LOGIN");
                                throw new XrootdException(kXR_NotAuthorized,
                                      "Login required");
                            case AUTH:
                                LOGGER.debug("Request kXR_auth isInProgress: AUTH");
                                throw new XrootdException(kXR_InvalidRequest,
                                      "Already authenticated");
                            default:
                                req.setSession(session);
                                handleAuthentication(ctx, (AuthenticationRequest) req);
                        }
                    } finally {
                        inProgress.set(false);
                    }
                } else {
                    throw new XrootdException(kXR_inProgress, "Login in progress");
                }
                break;
            case kXR_endsess:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_endsess");
                switch (state) {
                    case NO_LOGIN:
                        LOGGER.debug("Request kXR_endsess NO_LOGIN");
                        throw new XrootdException(kXR_NotAuthorized, "Login required");
                    case NO_AUTH:
                        LOGGER.debug("Request kXR_endsess NO_AUTH");
                        throw new XrootdException(kXR_NotAuthorized,
                              "Authentication required");
                }
                return doOnEndSession(ctx, (EndSessionRequest) req);
            case kXR_protocol:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_protocol");
                ctx.fireChannelRead(req);
                break;
            case kXR_bind:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_bind");
                if (tlsSessionInfo != null && tlsSessionInfo.serverUsesTls()) {
                    boolean isStarted = tlsSessionInfo.serverTransitionedToTLS(kXR_bind, ctx);
                    LOGGER.debug("kXR_bind, server has now transitioned to tls? {}.",
                          isStarted);
                }
                ctx.fireChannelRead(req);
                break;
            case kXR_ping:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request kXR_ping");
                if (!isLoginStarted()) {
                    LOGGER.debug("Request kXR_ping: NO LOGIN");
                    throw new XrootdException(kXR_NotAuthorized, "Login required");
                }
                req.setSession(session);
                ctx.fireChannelRead(req);
                break;
            default:
                LOGGER.debug("XrootdSessionHandler.getResponse: Request {}", req.getRequestId());
                switch (state) {
                    case NO_LOGIN:
                        LOGGER.debug("{}, NO LOGIN", req);
                        throw new XrootdException(kXR_NotAuthorized, "Login required");
                    case NO_AUTH:
                        LOGGER.debug("{}, NO_AUTH", req);
                        throw new XrootdException(kXR_NotAuthorized, "Authentication required");
                }
                req.setSession(session);
                ctx.fireChannelRead(req);
                break;
        }

        return null;
    }

    @Override
    protected LoginResponse doOnLogin(ChannelHandlerContext ctx, LoginRequest request)
          throws XrootdException {
        if (inProgress.compareAndSet(false, true)) {
            try {
                request.setUserName(UserNameUtils.checkUsernameValid(request.getUserName()));
                session = new XrootdSession(sessionId, ctx.channel(), request);
                request.setSession(session);
                LoginResponse response = new LoginResponse(request, sessionId,
                      protocolString());
                SESSIONS.put(sessionId, session);
                setLoginStarted();
                return response;
            } finally {
                inProgress.set(false);
            }
        } else {
            throw new XrootdException(kXR_inProgress, "Login in progress");
        }
    }

    @Override
    protected Object doOnEndSession(ChannelHandlerContext ctx, EndSessionRequest request)
          throws XrootdException {
        XrootdSessionIdentifier id = request.getSessionId();

        if (id.equals(CURRENT_SESSION_PLACEHOLDER)) {
            ctx.channel().close();
            return new OkResponse<>(request);
        }

        XrootdSession session = SESSIONS.get(id);

        if (session != null) {
            if (!session.hasOwner(this.session.getSubject())) {
                throw new XrootdException(kXR_NotAuthorized, "not session owner");
            }
            session.getChannel().close();
        }

        /*
         * If the session is not in the map, it has either been removed on another channel,
         * or it is unknown.  Either way, the vanilla server just sends back OK,
         * so we do the same.
         */
        return new OkResponse<>(request);
    }

    private void handleAuthentication(ChannelHandlerContext ctx, AuthenticationRequest request)
          throws XrootdException {
        if (currentHandler == null) {
            /*
             *  Match the protocol, add to pipeline right after it the proper handler, and
             *  keep a reference to the current handler.
             */
            currentProtocol = request.getCredType();
            currentHandler = handlerMap.get(currentProtocol);

            if (currentHandler == null) {
                throw new XrootdException(kXR_NotAuthorized, "server does not support "
                      + currentProtocol);
            }

            /*
             *  Check to see if we need TLS at login.
             */
            if (currentHandler instanceof RequiresTLS && !isTLSOn(ctx)) {
                throw new XrootdException(kXR_Unsupported,
                      "TLS is required for " + currentProtocol);
            }

            ctx.pipeline().addAfter(SESSION_HANDLER, currentProtocol, currentHandler);
        }
        ctx.fireChannelRead(request);
    }

    public boolean isLoginStarted() {
        return state != State.NO_LOGIN;
    }

    public void setLoginStarted() {
        state = State.NO_AUTH;
    }

    public void setAuthSucceeded(ChannelHandlerContext ctx) throws XrootdException {
        state = State.AUTH;
        if (tlsSessionInfo != null && tlsSessionInfo.serverUsesTls()) {
            boolean isStarted = tlsSessionInfo.serverTransitionedToTLS(kXR_auth, ctx);
            LOGGER.debug("kXR_auth, server has now transitioned to tls? {}.", isStarted);
        } else {
            AuthenticationHandler authHandler = currentHandler.getHandler();
            if (!(authHandler instanceof NoAuthenticationHandler) && !isTLSOn(ctx)
                  && signingPolicy.isSigningOn()) {
                /*
                 * Add the sigver decoder to the pipeline and remove the original
                 * message decoder.
                 *
                 * We only do this if we are in fact enforcing a protocol;
                 * hence the check that the handler is not the NOP placeholder.
                 */
                BufferDecrypter decrypter = authHandler.getDecrypter();
                ChannelPipeline pipeline = ctx.pipeline();
                XrootdDecoder decoder = (XrootdDecoder) pipeline.get("decoder");
                XrootdSigverDecoder sigverDecoder = new XrootdSigverDecoder(signingPolicy,
                      decrypter);
                sigverDecoder.setMaxWriteBufferSize(decoder.getMaxWriteBufferSize());
                ctx.pipeline().addAfter("decoder", "sigverDecoder",
                      sigverDecoder);
                ctx.pipeline().remove("decoder");
                LOGGER.debug("switched decoder to sigverDecoder, decrypter {}.", decrypter);
            }
        }
        ctx.pipeline().remove(currentHandler);
        currentHandler = null;
        currentProtocol = null;
    }

    public void setAuthFailed(ChannelHandlerContext ctx) {
        state = State.NO_AUTH;
        ctx.pipeline().remove(currentHandler);
        currentHandler = null;
        currentProtocol = null;
    }

    public void setSigningPolicy(SigningPolicy signingPolicy) {
        this.signingPolicy = signingPolicy;
    }

    public void setTlsSessionInfo(TLSSessionInfo tlsSessionInfo) {
        this.tlsSessionInfo = tlsSessionInfo;
    }

    private String protocolString() {
        String protocols =
              handlerMap.values().stream().map(h -> h.getHandler())
                    .map(AuthenticationHandler::getProtocol)
                    .collect(Collectors.joining());
        LOGGER.debug("protocols: {}.", protocols);
        return protocols;
    }
}
