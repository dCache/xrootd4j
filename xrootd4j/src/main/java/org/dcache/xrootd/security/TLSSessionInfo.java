/**
 * Copyright (C) 2011-2020 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.security;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.tls.SSLHandlerFactory;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.util.ServerProtocolFlags;
import org.dcache.xrootd.util.ServerProtocolFlags.TlsMode;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.TLSSessionInfo.TlsActivation.*;
import static org.dcache.xrootd.util.ServerProtocolFlags.TlsMode.OFF;

/**
 *  Used by both the server and the TPC client to determine when TLS
 *  should be activated.  Automatically adds the SSLHandler to the
 *  pipeline when activate is true.
 */
public class TLSSessionInfo
{
    private static final Logger LOGGER
                    = LoggerFactory.getLogger(TLSSessionInfo.class);

    private static void operationComplete(String origin,
                                          Future<Channel> future)
    {
        if (future.isSuccess()) {
            LOGGER.debug("{}: TLS handshake completed.", origin);
        } else {
            LOGGER.warn("{}: TLS handshake failed: {}.", origin,
                        String.valueOf(future.cause()));
        }
    }

    enum ClientTls
    {
        REQUIRES, ABLE, NONE;

        static ClientTls getMode(int version, int options)
        {
            if (version < PROTOCOL_TLS_VERSION) {
                return NONE;
            }

            if ((options & kXR_wantTLS) == kXR_wantTLS) {
                return REQUIRES;
            }

            if ((options & kXR_ableTLS) == kXR_ableTLS) {
                return ABLE;
            }

            return NONE;
        }
    }

    enum TlsActivation
    {
        NONE, LOGIN, SESSION, DATA, GPF, TPC;

        public static TlsActivation valueOf(ServerProtocolFlags flags)
        {
            if (flags.getMode() == OFF) {
                return NONE;
            }

            if (flags.requiresTLSForLogin()) {
                return LOGIN;
            } else if (flags.requiresTLSForData()) {
                return DATA;
            } else if (flags.requiresTLSForGPF()) {
                return GPF;
            } else if (flags.requiresTLSForSession()) {
                return SESSION;
            } else if (flags.requiresTLSForTPC()) {
                return TPC;
            } else {
                return NONE;
            }
        }
    }

    abstract class TlsSession implements FutureListener<Channel>
    {
        /**
         *   Server settings.
         */
        protected ServerProtocolFlags serverFlags;

        /**
         *   Client protocol flags.
         */
        protected int version;
        protected int options;
        protected int expect;

        /**
         *   For the Netty pipeline.
         */
        protected SslHandler        sslHandler;

        protected TlsSession()
        {
        }

        protected TlsSession(ServerProtocolFlags serverFlags)
        {
            this.serverFlags = new ServerProtocolFlags(serverFlags);
        }

        /**
         *   Fresh copy to recompute session on redirect, and not reuse
         *   the SslHandler placed in previous connection's pipeline.
         *
         *   @param other to clone
         */
        protected TlsSession(TlsSession other)
        {
            this.serverFlags = new ServerProtocolFlags(other.serverFlags);
            this.version = other.version;
            this.options = other.options;
            this.expect = other.expect;
        }

        protected void setClientFlags(int version,
                                   int options,
                                   int expect)
        {
            this.version = version;
            this.options = options;
            this.expect = expect;
            LOGGER.debug("Client version {}, options {}, expect {}.",
                        version, options, expect);
        }

        /**
         *   Sets up the tls configuration (whether and when to require it).
         *
         *   @throws XrootdException
         */
        protected abstract void configure() throws XrootdException;

        protected abstract boolean transitionedToTLS(int request,
                                                  ChannelHandlerContext ctx)
                        throws XrootdException;
    }

    /**
     *   For local door or pool.
     */
    class ServerTlsSession extends TlsSession
    {
        protected ServerTlsSession(ServerProtocolFlags localServerFlags)
        {
            super(localServerFlags);
        }

        protected ServerTlsSession(TlsSession other)
        {
            super(other);
        }

        protected void configure() throws XrootdException
        {
            ClientTls clientTls = ClientTls.getMode(version, options);

            if (clientTls == ClientTls.NONE) {
                LOGGER.debug("Client NOT TLS capable.");

                /*
                 *  Two cases of failure for non-capable clients.
                 *
                 *  (1) the source server mode is strict, not optional;
                 *
                 *  (2) this is the destination server,
                 *      TLS is required for TPC and the client intends
                 *      to do TPC.
                 *
                 *  The latter check cannot be done here, because
                 *      we do not know the protocol used to connect
                 *      to the source yet (an opaque data element
                 *      passed on the first path query).
                 */
                if (serverFlags.getMode() == TlsMode.STRICT) {
                    throw new XrootdException(kXR_TLSRequired,
                                              "Server accepts only secure "
                                                    + "connections.");
                }

                serverFlags.setMode(OFF);
                LOGGER.debug("TLS is OFF.");
                return;
            }

            if (serverFlags.getMode() == OFF) {
                LOGGER.debug("TLS is OFF.");
                if (clientTls == ClientTls.REQUIRES) {
                    throw new XrootdException(kXR_TLSRequired,
                                              "Server is not able to "
                                                              + "accept secure "
                                                              + "connections.");
                }
                return;
            }

            /*
             *  In the case of kXR_wantTLS, promote to login.
             */
            if (clientTls == ClientTls.REQUIRES) {
                LOGGER.debug("Client kXR_wantTLS.");
                serverFlags.setRequiresTLSForLogin(true);
                serverFlags.setGoToTLS(true);
                LOGGER.debug("setLocalTlsActivation, activation is now {}.",
                             LOGIN);
                return;
            }

            if (serverFlags.requiresTLSForLogin()) {
                serverFlags.setGoToTLS(true);
            }

            if (serverFlags.requiresTLSForData()) {
                if ((expect & kXR_ExpBind) == kXR_ExpBind) {
                    LOGGER.debug("Client kXR_ExpBind.");
                    serverFlags.setGoToTLS(true);
                }
            }

            if (serverFlags.requiresTLSForGPF()) {
                if ((expect & kXR_ExpGPF) == kXR_ExpGPF) {
                    LOGGER.debug("Client kXR_ExpGPF.");
                    serverFlags.setGoToTLS(true);
                }
            }

            /*
             *  It is up to the code which processes open to make sure
             *  that both tpc.spr and tpc.tpr conform to the requirements
             *  of the destination server on TPC.
             */
        }

        protected boolean transitionedToTLS(int request, ChannelHandlerContext ctx)
                        throws XrootdException
        {
            if (ctx.pipeline().get(SslHandler.class) != null) {
                return false;
            }

            TlsActivation tlsActivation
                            = TlsActivation.valueOf(serverFlags);

            LOGGER.debug("transitionedToTLS, server tlsActivation: {}.",
                         tlsActivation);

            /*
             *  TPC is not strong enough to warrant activation.
             *  It merely serves as a blocker for non-capable clients
             *  (they should not be able to do TPC if this flag is set).
             */
            if (tlsActivation == NONE || tlsActivation == TPC) {
                return false;
            }

            if (serverSslHandlerFactory == null) {
                throw new XrootdException(kXR_ServerError,
                                          "no ssl handler factory "
                                                          + "set on server.");
            }

            boolean activate = serverFlags.goToTLS();

            if (!activate) {
                switch (request)
                {
                    case kXR_protocol:
                        activate = tlsActivation == LOGIN;
                        break;
                    case kXR_bind:
                        activate = tlsActivation == DATA;
                        break;
                    default:
                        activate = true;
                        break;
                }
            }

            if (activate) {
                sslHandler = (SslHandler) serverSslHandlerFactory.createHandler();
                sslHandler.engine().setUseClientMode(false);
                sslHandler.engine().setNeedClientAuth(false);
                sslHandler.engine().setWantClientAuth(false);
                ctx.pipeline().addFirst(sslHandler);
                LOGGER.debug("PIPELINE addFirst:  SSLHandler need auth {}, "
                                             + "want auth {}, "
                                             + "client mode {}.",
                             sslHandler.engine().getNeedClientAuth(),
                             sslHandler.engine().getWantClientAuth(),
                             sslHandler.engine().getUseClientMode());
                sslHandler.handshakeFuture().addListener(this);
            }

            return activate;
        }

        @Override
        public void operationComplete(Future<Channel> future)
        {
            TLSSessionInfo.operationComplete("Server", future);
        }
    }

    /**
     *   For the TPC client.
     */
    class ClientTlsSession extends TlsSession
    {
        /**
         *  The TPC client only sets kXR_wantTLS when the client has
         *  expressed 'xroots' as the source server protocol (= tpc.spr)
         *  or the server requires TLS.
         *
         *  Otherwise, if the current server mode is not OFF, it will advertise
         *  itself as "kXR_ableTLS".
         */
        protected final boolean requiresTLS;

        protected ClientTlsSession(XrootdTpcInfo info)
        {
            requiresTLS = info.isTls();
        }

        protected void configure()
        {
            version = PROTOCOL_VERSION;

            /*
             *   Our tpc client will always do a login first.
             */
            expect = kXR_ExpLogin | kXR_ExpTPC;

            switch (serverSession.serverFlags.getMode()) {
                case OFF:
                    /*
                     *  Just ask for the source server
                     *  signing requirements.
                     */
                    options = kXR_secreqs;
                    break;
                default:
                    if (requiresTLS) {
                        options = kXR_wantTLS;
                    } else {
                        options = kXR_ableTLS | kXR_secreqs;
                    }
                    break;
            }
        }

        protected void setSourceServerFlags(int flags)
        {
            serverFlags = new ServerProtocolFlags(flags);
        }

        protected boolean transitionedToTLS(int request, ChannelHandlerContext ctx)
                        throws XrootdException
        {
            /*
             *  REVISIT
             *
             *  Currently this is different from version 5 xrootd servers,
             *  where TLS can be OFF but the TPC client nevertheless
             *  supports TLS.
             */
            if (!serverSession.serverFlags.supportsTLS()) {
                return false;
            }

            /*
             *  Initialized on preceding server response.
             */
            if (ctx.pipeline().get(SslHandler.class) != null) {
                return false;
            }

            /*
             *  We check this again here, because we may be speaking
             *  to a pre-version 5 server, which will not send any
             *  TLS flags at all.
             */
            if (!serverFlags.supportsTLS()) {
                if (requiresTLS) {
                    throw new XrootdException(kXR_TLSRequired,
                                              "Source is not able to "
                                                + "accept secure connections.");
                }

                return false;
            }

            if (clientSslHandlerFactory == null) {
                throw new XrootdException(kXR_ServerError,
                                          "no ssl handler factory set on "
                                                          + "third-party "
                                                          + "client.");

            }

            boolean activate = serverFlags.goToTLS();

            TlsActivation tlsActivation
                            = TlsActivation.valueOf(serverFlags);

            if (!activate) {
                switch (request)
                {
                    case kXR_login:
                        activate = tlsActivation == LOGIN;
                        break;
                    case kXR_bind:
                        activate = tlsActivation  == DATA;
                        break;
                    default:
                        /*
                         *  Xrootd does not consider 'TPC' on the
                         *  source server sufficient to trigger TLS.
                         */
                        activate = !(tlsActivation == TPC
                                        || tlsActivation == NONE);
                        break;
                }
            }

            if (activate) {
                sslHandler = (SslHandler)clientSslHandlerFactory.createHandler();
                sslHandler.engine().setUseClientMode(true);
                ctx.pipeline().addFirst(sslHandler);
                LOGGER.debug("PIPELINE addFirst:  SSLHandler need auth {}, "
                                             + "want auth, {}, "
                                             + "client mode {}.",
                             sslHandler.engine().getNeedClientAuth(),
                             sslHandler.engine().getWantClientAuth(),
                             sslHandler.engine().getUseClientMode());
                sslHandler.handshakeFuture().addListener(this);
                LOGGER.info("TPC client initiating SSL handshake");
            }

            return activate;
        }

        @Override
        public void operationComplete(Future<Channel> future)
        {
            TLSSessionInfo.operationComplete("TPC client", future);
        }
    }

    /**
     *   Local door or pool session.
     */
    private final ServerTlsSession serverSession;

    /**
     *   Tpc client session.
     */
    private ClientTlsSession tpcClientSession;

    /**
     *   Factory for server pipeline.
     *
     *   Constructs SslHandler with parameter 'startTls' = true.
     */
    private SSLHandlerFactory serverSslHandlerFactory;

    /**
     *   Factory for tpc client pipeline.
     *
     *   Constructs SslHandler with parameter 'startTls' = false.
     */
    private SSLHandlerFactory clientSslHandlerFactory;

    public TLSSessionInfo(ServerProtocolFlags serverFlags)
    {
        serverSession = new ServerTlsSession(serverFlags);
    }

    /**
     * @param other to clone from
     */
    public TLSSessionInfo(TLSSessionInfo other)
    {
        serverSession = new ServerTlsSession(other.serverSession);
        clientSslHandlerFactory = other.clientSslHandlerFactory;
        serverSslHandlerFactory = other.serverSslHandlerFactory;
    }

    /**
     * This method should be called by the TPC client
     * before the relevant requests.
     *
     * @param request to be sent to the remote server.
     * @param ctx for access to pipeline.
     * @return whether the SSLHandler was added the pipeline.
     */
    public boolean clientTransitionedToTLS(int request,
                                           ChannelHandlerContext ctx)
                    throws XrootdException
    {
        boolean response = tpcClientSession.transitionedToTLS(request, ctx);
        LOGGER.debug("client transitioned to TLS ? {}.", response);
        return response;
    }

    public boolean clientUsesTls()
    {
        ClientTls clientTls = ClientTls.getMode(tpcClientSession.version,
                                                tpcClientSession.options);
        boolean response = (clientTls != ClientTls.NONE);
        LOGGER.debug("client uses TLS ? {}.", response);
        return response;
    }

    public void createClientSession(XrootdTpcInfo info)
    {
        tpcClientSession = new ClientTlsSession(info);
        tpcClientSession.configure();
    }

    public boolean isIncomingClientTLSCapable()
    {
        ClientTls clientTls = ClientTls.getMode(serverSession.version,
                                                serverSession.options);
        boolean response = clientTls != ClientTls.NONE;
        LOGGER.debug("isClientTLSCapable ? {}.", response);
        return response;
    }

    /**
     *  Called by the TPC client.
     *
     * @param sourceServerFlags from the protocol response
     */
    public void setSourceServerFlags(int sourceServerFlags)
    {
        LOGGER.debug("setSourceServerFlags {}.", sourceServerFlags);
        tpcClientSession.setSourceServerFlags(sourceServerFlags);
    }

    public int[] getClientFlags()
    {
        return new int[]{tpcClientSession.version,
                         tpcClientSession.options,
                         tpcClientSession.expect};
    }

    public String getClientTls()
    {
        return ClientTls.getMode(tpcClientSession.version,
                                 tpcClientSession.options).name();
    }

    public ServerProtocolFlags getLocalServerProtocolFlags()
    {
        return serverSession.serverFlags;
    }

    /**
     * This method should be called by the server during the response to
     * the relevant requests.
     *
     * @param request to which the server is responding.
     * @param ctx for access to pipeline.
     * @return whether the SSLHandler was added the pipeline.
     */
    public boolean serverTransitionedToTLS(int request,
                                           ChannelHandlerContext ctx)
                    throws XrootdException
    {
        boolean response = serverSession.transitionedToTLS(request, ctx);
        LOGGER.debug("server transitioned to TLS ? {}.", response);
        return response;
    }

    public boolean serverUsesTls()
    {
        boolean response = TlsActivation.valueOf(serverSession.serverFlags)
                        != NONE;
        LOGGER.debug("server uses TLS ? {}.", response);
        return response;
    }

    public void setClientSslHandlerFactory(SSLHandlerFactory sslHandlerFactory)
    {
        this.clientSslHandlerFactory = sslHandlerFactory;
    }

    /**
     * Used by the server side to determine response to client,
     * depending on its own configuration and the client flags.
     *
     * This is called during the protocol request-response phase.
     *
     * @param clientOptions whether it supports or requests TLS.
     * @param clientExpect what the next request will be (optional).
     *
     */
    public void setLocalTlsActivation(int version,
                                      int clientOptions,
                                      int clientExpect)
                    throws XrootdException
    {
        LOGGER.debug("setLocalTlsActivation {}, {}, {}.",
                     version, clientExpect, clientOptions);
        serverSession.setClientFlags(version, clientOptions, clientExpect);
        serverSession.configure();
    }

    public void setServerSslHandlerFactory(SSLHandlerFactory serverSslHandlerFactory)
    {
        this.serverSslHandlerFactory = serverSslHandlerFactory;
    }
}
