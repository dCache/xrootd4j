/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdSessionIdentifier;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.tpc.core.XrootdClientDecoder;
import org.dcache.xrootd.tpc.core.XrootdClientEncoder;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundCloseRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundEndSessionRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundHandshakeRequest;
import org.dcache.xrootd.util.OpaqueStringParser;

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

    private static int lastId = 1;

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
    private final String                     fullpath;

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
         *  Reuse the original uname and pid
         *  when sending to the source server.
         *
         *  Thus the source will see the client contact as uname.pid@clienthost
         *  and the dCache pool contact as uname.pid@poolhost.
         */
        uname = userSplit[0];
        pid = Integer.parseInt(userSplit[1]);

        String external = info.getExternal();
        if (external == null) {
            external = "";
        } else {
            external = OpaqueStringParser.OPAQUE_PREFIX + external;
        }

        fullpath = info.getLfn()
                        + OpaqueStringParser.OPAQUE_STRING_PREFIX
                        + XrootdTpcInfo.RENDEZVOUS_KEY
                        + OpaqueStringParser.OPAQUE_SEPARATOR
                        + info.getKey()
                        + OpaqueStringParser.OPAQUE_PREFIX
                        + XrootdTpcInfo.CLIENT
                        + OpaqueStringParser.OPAQUE_SEPARATOR
                        + userUrn
                        + external;

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

        channelFuture = b.connect(info.getSrcHost(), info.getSrcPort()).sync();

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
        LOGGER.trace("sendCloseRequest to {}, channel {}, stream {}, fhandle {}.",
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
            LOGGER.trace("sendEndSessionRequest to {}, channel {}, stream {}, "
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
            LOGGER.trace("sendEndSessionRequest to {}, channel {}, stream {}, session was null.",
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
                    throws InterruptedException
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
        executorService.schedule(new Runnable() {
            @Override
            public void run() {
                disconnect();
            }
        }, 5, TimeUnit.SECONDS);
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
        LOGGER.trace("Client asked for full path: {}.", this);
        return fullpath;
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

        if (t instanceof ClosedChannelException) {
            errno = kXR_ServerError;
        } else if (t instanceof IOException) {
            errno = kXR_IOError;
        } else if (t instanceof RuntimeException) {
            errno = kXR_ServerError;
        } else {
            errno = kXR_error;
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

    public void setSessionId(XrootdSessionIdentifier sessionId)
    {
        this.sessionId = sessionId;
    }

    public void setSigningPolicy(SigningPolicy signingPolicy)
    {
        this.signingPolicy = signingPolicy;
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
                                  .append(fullpath)
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

    private void injectHandlers(ChannelPipeline pipeline,
                                List<ChannelHandlerFactory> plugins,
                                TpcSourceReadHandler readHandler)
    {
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
        LOGGER.trace("sendHandshakeRequest to {}, channel {}, stream {}.",
                     info.getSrc(), ctx.channel().id(), streamId);
        ctx.writeAndFlush(new OutboundHandshakeRequest(),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }
}
