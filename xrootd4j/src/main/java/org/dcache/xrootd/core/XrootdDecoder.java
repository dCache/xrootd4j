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
package org.dcache.xrootd.core;

import com.google.common.base.Strings;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import org.dcache.xrootd.protocol.messages.AbstractXrootdRequest;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.LocateRequest;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.QueryRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.SetRequest;
import org.dcache.xrootd.protocol.messages.SigverRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.UnknownRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secNone;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secOFrce;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_signIgnore;

/**
 * A FrameDecoder decoding xrootd frames into AbstractRequestMessage
 * objects.
 *
 * TODO: Implement zero-copy handling of write requests by splitting
 * the request into fragments.
 */
public class XrootdDecoder extends ByteToMessageDecoder
{
    private static final Logger _logger =
        LoggerFactory.getLogger(XrootdDecoder.class);

    private final int secLvl;
    private final byte secOFrce;

    /**
     * <p>The default handler which has no encryption/decryption
     *    capabilities.  It may be that signing is forced on
     *    non-encrypted protocols.</p>
     *
     * <p>If an authentication handler exists on the pipeline,
     *    it will potentially override this handler with one
     *    containing its encryption/decryption type.</p>
     */
    private XrootdSigverRequestHandler sigverRequestHandler
        = new XrootdSigverRequestHandler();

    public XrootdDecoder()
    {
        this(kXR_secNone, (byte)0);
    }

    public XrootdDecoder(int secLvl, byte secOFrce)
    {
        this.secLvl = secLvl;
        this.secOFrce = secOFrce;
    }

    public synchronized XrootdSigverRequestHandler getSigverRequestHandler()
    {
        return sigverRequestHandler;
    }

    public synchronized void setSigverRequestHandler(XrootdSigverRequestHandler handler)
    {
        sigverRequestHandler = handler;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
    {
        int readable = in.readableBytes();

        /* All other requests have a common framing format with a
         * fixed length header.
         */
        if (readable < CLIENT_REQUEST_LEN) {
            return;
        }

        int pos = in.readerIndex();
        int headerFrameLength = in.getInt(pos + 20);

        if (headerFrameLength < 0) {
            _logger.error("Received illegal frame length in xrootd header: {}."
                          + " Closing channel.", headerFrameLength);
            ctx.channel().close();
            return;
        }

        int length = CLIENT_REQUEST_LEN + headerFrameLength;

        if (readable < length) {
            return;
        }

        ByteBuf frame = in.readSlice(length);
        int requestID = frame.getUnsignedShort(2);
        AbstractXrootdRequest request = null;

        try {
            switch (requestID) {
                case kXR_sigver:
                    if (sigverRequestHandler == null) {
                        throw new XrootdException(kXR_ServerError,
                                                  "server session not set to handle "
                                                                  + "sigver request");
                    }

                    sigverRequestHandler.setSigver(new SigverRequest(frame));
                    return;
                case kXR_login:
                    request = new LoginRequest(frame);
                    break;
                case kXR_prepare:
                    request = new PrepareRequest(frame);
                    break;
                case kXR_open:
                    request = new OpenRequest(frame);
                    break;
                case kXR_stat:
                    request = new StatRequest(frame);
                    break;
                case kXR_statx:
                    request = new StatxRequest(frame);
                    break;
                case kXR_read:
                    request = new ReadRequest(frame);
                    break;
                case kXR_readv:
                    request = new ReadVRequest(frame);
                    break;
                case kXR_write:
                    request = new WriteRequest(frame);
                    break;
                case kXR_sync:
                    request = new SyncRequest(frame);
                    break;
                case kXR_close:
                    request = new CloseRequest(frame);
                    break;
                case kXR_protocol:
                    request = new ProtocolRequest(frame);
                    break;
                case kXR_rm:
                    request = new RmRequest(frame);
                    break;
                case kXR_rmdir:
                    request = new RmDirRequest(frame);
                    break;
                case kXR_mkdir:
                    request = new MkDirRequest(frame);
                    break;
                case kXR_mv:
                    request = new MvRequest(frame);
                    break;
                case kXR_dirlist:
                    request = new DirListRequest(frame);
                    break;
                case kXR_auth:
                    request = new AuthenticationRequest(frame);
                    break;
                case kXR_endsess:
                    request = new EndSessionRequest(frame);
                    break;
                case kXR_locate:
                    request = new LocateRequest(frame);
                    break;
                case kXR_query:
                    request = new QueryRequest(frame);
                    break;
                case kXR_set:
                    request = new SetRequest(frame);
                    break;
                default:
                    request = new UnknownRequest(frame);
                    break;
            }

            out.add(verifySignedHash(frame, request, ctx));
        } catch (XrootdException e) {
            _logger.error("Error when decoding request {}, stream {}, channel {}: {}",
                          request.getRequestId(), request.getStreamId(),
                          ctx.channel().id(), e.toString());
            ErrorResponse response = new ErrorResponse<>(request,
                                                         e.getError(),
                                                         Strings.nullToEmpty(e.getMessage()));
            ctx.writeAndFlush(response)
               .addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
        }
    }

    private AbstractXrootdRequest verifySignedHash(ByteBuf frame,
                                                   AbstractXrootdRequest request,
                                                   ChannelHandlerContext ctx)
                    throws XrootdException
    {
        if (!request.isSigned(secLvl, kXR_signIgnore)) { // no override
            return request;
        }

        boolean force = secOFrce == kXR_secOFrce;

        _logger.trace("calling verify signed hash for {}, force {}.",
                     request, force);

        return getSigverRequestHandler().verifySignedHash(frame,
                                                          request,
                                                          force,
                                                          ctx);
    }
}
