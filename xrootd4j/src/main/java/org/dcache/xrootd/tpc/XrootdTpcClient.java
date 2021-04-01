/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc;

import com.google.common.base.Strings;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.core.XrootdSessionIdentifier;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.tpc.XrootdTpcInfo.Delegation;
import org.dcache.xrootd.tpc.core.XrootdClientDecoder;
import org.dcache.xrootd.tpc.core.XrootdClientEncoder;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundCloseRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundEndSessionRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundHandshakeRequest;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>Internal third-party copy client responsible for reading the
 *    source file and writing it to the local server.</p>
 *
 * <p>A TpcClient is responsible for a single file transfer.
 *    It has its own channel/pipeline, and its lifecycle ends with the
 *    completion of the transfer, whereupon it is disconnected.</p>
 *
 * <p>A client is bound to its channel handlers through injection.</p>
 */
public class XrootdTpcClient
{
    private static final Logger              LOGGER
                    = LoggerFactory.getLogger(XrootdTpcClient.class);

    private static final int DISCONNECT_TIMEOUT_IN_SECONDS = 5;
    private static final int DEFAULT_RESPONSE_TIMEOUT_IN_SECONDS = 30;

    private static int lastId = 1;

    /**
     * The pid is used for monitoring purposes on the xrootd end.
     * In order to imitate xrootd, which execs the TPC client,
     * we just generate a random five-digit number here.
     *
     * @return "pid" for the TPC client
     */
    private static synchronized int getClientPid()
    {
        return ThreadLocalRandom.current().nextInt(99999);
    }

    /**
     *  Stream value of 0 is reserved for initial handshakes.
     *  Also watch for overflow.
     */
    private static synchronized int getNextStreamId() {
        if (lastId < 0) {
            lastId = 1;
        }
        return lastId++;
    }

    private final int                        streamId;
    private final String                     userUrn;
    private final XrootdTpcInfo              info;
    private final TpcDelayedSyncWriteHandler writeHandler;
    private final Map<String, Object>        authnContext;
    private final Map<String, ChannelHandler> authnHandlers;
    private final int                        pid;
    private final String                     uname;

    private final ScheduledExecutorService executorService;

    private int                           expectedRequestId;
    private InboundAuthenticationResponse authResponse;

    /*
     *  From the handshake.
     */
    private int pval;
    private int flag;

    /*
     *  Login/session
     */
    private XrootdSessionIdentifier sessionId;

    /*
     *  Hash signing configuration
     */
    private SigningPolicy signingPolicy;

    /*
     *  Whether to use startTLS.
     */
    private TLSSessionInfo tlsSessionInfo;

    /*
     * Open
     */
    private int     cpsize;
    private int     cptype;
    private int     fhandle;
    private boolean isOpenFile;

    /*
     * Read => write.
     */
    private long writeOffset;

    /*
     * Netty
     */
    private ChannelFuture              channelFuture;

    private int errno;
    private String error;

    private boolean isRunning;
    private int redirects;
    private long timeOfFirstRedirect;
    private long responseTimeout = DEFAULT_RESPONSE_TIMEOUT_IN_SECONDS;

    private ScheduledFuture timerTask;

    public XrootdTpcClient(String userUrn,
                           XrootdTpcInfo info,
                           TpcDelayedSyncWriteHandler writeHandler,
                           ScheduledExecutorService executorService)
    {
        this.streamId = getNextStreamId();
        this.info = info;
        this.writeHandler = writeHandler;
        this.expectedRequestId = kXR_handshake;
        this.authnContext = new HashMap<>();
        this.authnHandlers = new HashMap<>();
        this.executorService = executorService;

        /*
         * urn for the user client that initiated the TPC
         */
        this.userUrn = userUrn;
        String user = userUrn.split("@")[0];
        String[] userSplit = user.split("[.]");

        /*
         *  Reuse the original uname
         *  when sending to the source server.
         *
         *  Thus the source will see the client contact as uname.pid@clienthost
         *  and the dCache pool contact as uname.pid@poolhost.
         */
        uname = userSplit[0];
        pid = getClientPid();
        writeOffset = 0L;
        errno = kXR_ok;
        redirects = 0;
        timeOfFirstRedirect = 0;
    }

    public synchronized boolean canRedirect()
    {
        if (redirects >= 256 &&
                System.currentTimeMillis() - timeOfFirstRedirect
                            >= TimeUnit.MINUTES.toMillis(10)) {
                return false;
        }

        return true;
    }

    public void configureRedirects(XrootdTpcClient preceding)
    {
        this.redirects = preceding.redirects + 1;
        this.timeOfFirstRedirect = preceding.timeOfFirstRedirect <= 0 ?
                        System.currentTimeMillis() :
                        preceding.timeOfFirstRedirect;
        this.responseTimeout = preceding.responseTimeout;
    }

    public synchronized void connect(final NioEventLoopGroup group,
                        final List<ChannelHandlerFactory> plugins,
                        final TpcSourceReadHandler readHandler)
                    throws InterruptedException
    {
        Bootstrap b = new Bootstrap();
        b.group(group)
         .channel(NioSocketChannel.class)
         .option(ChannelOption.TCP_NODELAY, true)
         .option(ChannelOption.SO_KEEPALIVE, true)
         .handler(new ChannelInitializer<Channel>() {
             @Override
             protected void initChannel(Channel ch) throws Exception {
                 injectHandlers(ch.pipeline(), plugins, readHandler);
             }
         });

        try {
            channelFuture = b.connect(info.getSrcHost(),
                                      info.getSrcPort()).sync();
        } catch (Exception t) {
            /*
             *  For some reason, doing the following:
             *
             *     channelFuture.addListener((f) -> {
             *         if (!f.isSuccess()) {
             *            setError(f.cause());
             *         }
             *     });
             *
             *  does not allow us to intercept the error early enough
             *  to process it for a bit more information.
             *
             *  So we have to resort to catching Exception.
             */
            setError(t);
            if (t instanceof RuntimeException) {
                throw (RuntimeException)t;
            }
            return;
        }

        isRunning = true;

        notifyAll();

        sendHandshakeRequest(channelFuture.channel().pipeline().lastContext());

        LOGGER.info("Third-party client started for {}, channel {}. stream {}.",
                     info.getSrc(),
                     channelFuture.channel().id(),
                     streamId);
    }

    /**
     * <p>Blocking call, returns when client is no longer running.</p>
     */
    public synchronized void disconnect()
    {
        if (!isRunning) {
            return;
        }

        ChannelId id = null;
        if (channelFuture != null) {
            id = channelFuture.channel().id();
            channelFuture.channel().close();
        }

        isRunning = false;

        notifyAll();

        LOGGER.info("Third-party client stopped, for {}, channel {}, stream {}.",
                     info.getSrc(), id, streamId);
    }

    public void doClose(ChannelHandlerContext ctx)
    {
        LOGGER.debug("sendCloseRequest to {}, channel {}, stream {}, fhandle {}.",
                     info.getSrc(),
                     ctx.channel().id(),
                     streamId,
                     fhandle);
        expectedRequestId = kXR_close;
        ctx.writeAndFlush(new OutboundCloseRequest(streamId, fhandle),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    public void doEndsession(ChannelHandlerContext ctx)
    {
        if (sessionId != null) {
            LOGGER.debug("sendEndSessionRequest to {}, channel {}, stream {}, "
                                         + "session {}.",
                         info.getSrc(),
                         ctx.channel().id(),
                         streamId,
                         sessionId);
            expectedRequestId = kXR_endsess;
            ctx.writeAndFlush(new OutboundEndSessionRequest(streamId, sessionId),
                              ctx.newPromise())
               .addListener(FIRE_EXCEPTION_ON_FAILURE);
            sessionId = null;
        } else {
            LOGGER.debug("sendEndSessionRequest to {}, channel {}, stream {}, session was null.",
                        info.getSrc(),
                        ctx.channel().id(),
                        streamId);
            disconnect();
        }
    }

    public ScheduledExecutorService getExecutor()
    {
        return executorService;
    }

    public synchronized void shutDown(ChannelHandlerContext ctx)
    {
        if (!isRunning) {
            return;
        }

        if (isOpenFile) {
            LOGGER.info("shutDown, doing close");
            doClose(ctx);
        } else {
            LOGGER.info("shutDown, doing endsession");
            doEndsession(ctx);
        }

        /*
         * It is not predictable whether the server will reply to an
         * endsession request, so this timed delay guarantees shutdown.
         */
        executorService.schedule(() -> disconnect(),
                                 DISCONNECT_TIMEOUT_IN_SECONDS,
                                 TimeUnit.SECONDS);
    }

    public synchronized void startTimer(final ChannelHandlerContext ctx) {
        /*
         *  just in case ...
         */
        stopTimer();
        timerTask = executorService.schedule(() ->
                                             {
                                                 setError(getTimeoutException());
                                                 shutDown(ctx);
                                             },
                                             responseTimeout,
                                             TimeUnit.SECONDS);
    }

    public synchronized void stopTimer() {
        if (timerTask != null) {
            timerTask.cancel(true);
            timerTask = null;
        }
    }

    public ChannelFuture getChannelFuture()
    {
        return channelFuture;
    }

    public Map<String, Object> getAuthnContext()
    {
        return authnContext;
    }

    public Map<String, ChannelHandler> getAuthnHandlers()
    {
        return authnHandlers;
    }

    public InboundAuthenticationResponse getAuthResponse()
    {
        return authResponse;
    }

    public int getCpsize()
    {
        return cpsize;
    }

    public int getCptype()
    {
        return cptype;
    }

    public int getErrno()
    {
        return errno;
    }

    public String getError()
    {
        return error;
    }

    public int getExpectedResponse()
    {
        return expectedRequestId;
    }

    public int getFhandle()
    {
        return fhandle;
    }

    public int getFlag()
    {
        return flag;
    }

    public String getFullpath()
    {
        StringBuilder fullPath = new StringBuilder();

        /*
         *  If the source token exists, put it first.
         */
        String sourceToken = info.getSourceToken();
        if (sourceToken != null) {
            fullPath.append(XrootdTpcInfo.AUTHZ)
                    .append(OpaqueStringParser.OPAQUE_SEPARATOR)
                    .append(sourceToken);
        }

        /*
         *  If delegation is not being used, forward the rendezvous key and
         *  client info.
         */
        if (info.getDlgon() == Delegation.OFF) {
            if (fullPath.length() > 0) {
                fullPath.append(OpaqueStringParser.OPAQUE_PREFIX);
            }
            fullPath.append(XrootdTpcInfo.CLIENT)
                    .append(OpaqueStringParser.OPAQUE_SEPARATOR)
                    .append(userUrn)
                    .append(OpaqueStringParser.OPAQUE_PREFIX)
                    .append(XrootdTpcInfo.RENDEZVOUS_KEY)
                    .append(OpaqueStringParser.OPAQUE_SEPARATOR)
                    .append(info.getKey());
        }

        String external = info.getExternal();
        if (!Strings.isNullOrEmpty(external)) {
            if (fullPath.length() > 0) {
                fullPath.append(OpaqueStringParser.OPAQUE_PREFIX);
            }
            fullPath.append(external);
        }

        if (fullPath.length() > 0) {
            fullPath.insert(0, OpaqueStringParser.OPAQUE_STRING_PREFIX);
        }

        fullPath.insert(0, info.getLfn());

        return fullPath.toString();
    }

    public XrootdTpcInfo getInfo()
    {
        return info;
    }

    public int getPid()
    {
        return pid;
    }

    public int getPval()
    {
        return pval;
    }

    public XrootdSessionIdentifier getSessionId()
    {
        return sessionId;
    }

    public SigningPolicy getSigningPolicy()
    {
        return signingPolicy;
    }

    public int getStreamId()
    {
        return streamId;
    }

    public TLSSessionInfo getTlsSessionInfo()
    {
        return tlsSessionInfo;
    }

    public String getUname()
    {
        return uname;
    }

    public String getUserUrn()
    {
        return this.userUrn;
    }

    public TpcDelayedSyncWriteHandler getWriteHandler()
    {
        return writeHandler;
    }

    public long getWriteOffset()
    {
        return writeOffset;
    }

    public boolean isOpenFile()
    {
        return isOpenFile;
    }

    public void setAuthResponse(InboundAuthenticationResponse authResponse)
    {
        this.authResponse = authResponse;
    }

    public void setCpsize(int cpsize)
    {
        this.cpsize = cpsize;
    }

    public void setCptype(int cptype)
    {
        this.cptype = cptype;
    }

    public void setError(Throwable t)
    {
        error = t.getMessage();

        if (t instanceof XrootdException) {
            errno = ((XrootdException)t).getError();
        } else if (t instanceof UnknownHostException) {
            error = "Invalid address: " + error;
            errno = kXR_FSError;
        } else if (t instanceof IOException) {
            errno = kXR_IOError;
        } else if (t instanceof ParseException) {
            errno = kXR_ArgInvalid;
        } else {
            errno = kXR_ServerError;
        }

        writeHandler.fireDelayedSync(errno, error);
    }


    public void setExpectedResponse(int expectedRequestId)
    {
        this.expectedRequestId = expectedRequestId;
    }

    public void setFhandle(int fhandle)
    {
        this.fhandle = fhandle;
    }

    public void setFlag(int flag)
    {
        this.flag = flag;
    }

    public void setOpenFile(boolean openFile)
    {
        isOpenFile = openFile;
    }

    public void setPval(int pval)
    {
        this.pval = pval;
    }

    public void setResponseTimeout(long responseTimeout) {
        this.responseTimeout = responseTimeout;
    }

    public void setSessionId(XrootdSessionIdentifier sessionId)
    {
        this.sessionId = sessionId;
    }

    public void setSigningPolicy(SigningPolicy signingPolicy)
    {
        this.signingPolicy = signingPolicy;
    }

    public void setTlsSessionInfo(TLSSessionInfo tlsSessionInfo)
    {
        this.tlsSessionInfo = tlsSessionInfo;
    }

    public void setWriteOffset(long writeOffset)
    {
        this.writeOffset = writeOffset;
    }

    public String toString()
    {
        return new StringBuilder().append("(RUNNING ")
                                  .append(isRunning)
                                  .append(")[info ")
                                  .append(info)
                                  .append("](channelId ")
                                  .append(channelFuture == null ? "?" :
                                          channelFuture.channel().id())
                                  .append(")(streamId ")
                                  .append(streamId)
                                  .append(")(userUrn ")
                                  .append(userUrn)
                                  .append(")(authnContext ")
                                  .append(authnContext)
                                  .append(")(pid ")
                                  .append(pid)
                                  .append(")(uname ")
                                  .append(uname)
                                  .append(")(fullpath ")
                                  .append(getFullpath())
                                  .append(")(expectedRequestId ")
                                  .append(expectedRequestId)
                                  .append(")(pval ")
                                  .append(pval)
                                  .append(")(flag ")
                                  .append(flag)
                                  .append(")(sessionId ")
                                  .append(sessionId)
                                  .append(")")
                                  .append(signingPolicy)
                                  .append(")(tls ")
                                  .append(tlsSessionInfo != null ?
                                          tlsSessionInfo.getClientTls() : "NONE")
                                  .append("(cpsize ")
                                  .append(cpsize)
                                  .append(")(cptype ")
                                  .append(cptype)
                                  .append(")(fhandle ")
                                  .append(fhandle)
                                  .append(")(isOpenFile ")
                                  .append(isOpenFile)
                                  .append(")(writeOffset ")
                                  .append(writeOffset)
                                  .append(")(errno ")
                                  .append(errno)
                                  .append(")(error ")
                                  .append(error)
                                  .append(")(redirects ")
                                  .append(redirects)
                                  .append(")(last redirect ")
                                  .append(new Date(timeOfFirstRedirect))
                                  .append(")")
                                  .toString();
    }

    private TimeoutException getTimeoutException() {
        return new TimeoutException("No response from server after "
                                                    + responseTimeout
                                                    + " seconds.");
    }

    private void injectHandlers(ChannelPipeline pipeline,
                                List<ChannelHandlerFactory> plugins,
                                TpcSourceReadHandler readHandler)
    {
        if (LOGGER.isTraceEnabled()) {
            pipeline.addLast("logger", new LoggingHandler(XrootdTpcClient.class,
                                                             LogLevel.TRACE));
        } else if (LOGGER.isDebugEnabled()) {
            pipeline.addLast("logger", new LoggingHandler(XrootdTpcClient.class));
        }

        pipeline.addLast("decoder", new XrootdClientDecoder(this));
        pipeline.addLast("encoder", new XrootdClientEncoder(this));

        AbstractClientRequestHandler handler = new TpcClientConnectHandler();
        handler.setClient(this);
        pipeline.addLast("connect", handler);
        readHandler.setClient(this);
        pipeline.addLast("read", readHandler);

        /*
         *  These are deferred until loaded in the order specified by the server
         *  when the client receives the login response.
         */
        for (ChannelHandlerFactory factory : plugins) {
            ChannelHandler authHandler = factory.createHandler();
            if (authHandler instanceof AbstractClientRequestHandler) {
                ((AbstractClientRequestHandler)authHandler).setClient(this);
            }
            authnHandlers.put(factory.getName(), authHandler);
        }
    }

    private void sendHandshakeRequest(ChannelHandlerContext ctx)
    {
        /*
         *  Create the client's tls session.
         *  It will be configured when the protocol response is received.
         */
        tlsSessionInfo.createClientSession(getInfo());

        LOGGER.debug("sendHandshakeRequest to {}, channel {}, stream {}.",
                     info.getSrc(), ctx.channel().id(), streamId);
        ctx.writeAndFlush(new OutboundHandshakeRequest(),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }
}
