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
package org.dcache.xrootd.tpc.core;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.tpc.protocol.messages.HandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundCloseResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundEndSessionResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundOpenReadOnlyResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitResponse;
import org.dcache.xrootd.tpc.protocol.messages.XrootdInboundResponse;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>FrameDecoder for translating xrootd frames into
 * {@link XrootdInboundResponse} objects.</p>.
 *
 * <p>Intended to support third-party client requests to a source server.</p>
 *
 * <p>Not thread safe. Instance should be bound to a single client session
 *    at a time.</p>
 */
public class XrootdClientDecoder extends ByteToMessageDecoder
{
    private static final Logger LOGGER =
                    LoggerFactory.getLogger(XrootdClientDecoder.class);

    private int requestId;

    public int getExpectedResponse() {
        return requestId;
    }

    public void setExpectedResponse(int requestId)
    {
        this.requestId = requestId;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in,
                          List<Object> out)
    {
        int readable = in.readableBytes();

        if (readable < SERVER_RESPONSE_LEN) {
            return;
        }

        int pos = in.readerIndex();
        int headerFrameLength = in.getInt(pos + 4);

        if (headerFrameLength < 0) {
            LOGGER.trace("Received illegal frame length in xrootd header: {}."
                                         + " Closing channel.",
                         headerFrameLength);
            ctx.channel().close();
            return;
        }

        int length = SERVER_RESPONSE_LEN + headerFrameLength;

        if (readable < length) {
            return;
        }

        ByteBuf frame = in.readSlice(length);

        /*
         *  Need to check if the status is 4006.
         */

        int stat = frame.getUnsignedByte(2);

        try {
            if (stat == kXR_waitresp) {
                LOGGER.trace("adding wait response.");
                out.add(new InboundWaitResponse(frame, requestId));
                return;
            }

            switch (requestId) {
                case kXR_handshake:
                    LOGGER.trace("adding handshake response.");
                    out.add(new HandshakeResponse(frame));
                    break;
                case kXR_login:
                    LOGGER.trace("adding login response.");
                    out.add(new InboundLoginResponse(frame));
                    break;
                case kXR_auth:
                    LOGGER.trace("adding authentication response.");
                    out.add(new InboundAuthenticationResponse(frame));
                    break;
                case kXR_open:
                    LOGGER.trace("adding open response.");
                    out.add(new InboundOpenReadOnlyResponse(frame));
                    break;
                case kXR_read:
                    LOGGER.trace("adding read response.");
                    out.add(new InboundReadResponse(frame));
                    break;
                case kXR_close:
                    LOGGER.trace("adding close response.");
                    out.add(new InboundCloseResponse(frame));
                    break;
                case kXR_endsess:
                    LOGGER.trace("adding endsess response.");
                    out.add(new InboundEndSessionResponse(frame));
                    break;
                default:
                    throw new XrootdException(XrootdProtocol.kXR_error,
                                              "Client should not have received "
                                                              + "response for "
                                                              + "this request type.");
            }
        } catch (XrootdException e) {
            LOGGER.trace("Error for request type {}: {}. Closing channel.",
                         requestId, e.getMessage());
            ctx.channel().close();
        }
    }
}
