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
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.core;

import io.netty.handler.codec.ByteToMessageDecoder;

import io.netty.channel.ChannelHandlerContext;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import org.dcache.xrootd.protocol.messages.*;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

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

    private boolean gotHandshake = false;

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
    {
        int readable = in.readableBytes();

        /* The first 20 bytes form a handshake.
         */
        if (!gotHandshake) {
            if (readable < CLIENT_HANDSHAKE_LEN) {
                return;
            }
            gotHandshake = true;

            out.add(new HandshakeRequest(in.readSlice(CLIENT_HANDSHAKE_LEN)));
            return;
        }

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

        switch (requestID) {
        case kXR_login:
            out.add(new LoginRequest(frame));
            break;
        case kXR_prepare:
            out.add(new PrepareRequest(frame));
            break;
        case kXR_open:
            out.add(new OpenRequest(frame));
            break;
        case kXR_stat:
            out.add(new StatRequest(frame));
            break;
        case kXR_statx:
            out.add(new StatxRequest(frame));
            break;
        case kXR_read:
            out.add(new ReadRequest(frame));
            break;
        case kXR_readv:
            out.add(new ReadVRequest(frame));
            break;
        case kXR_write:
            out.add(new WriteRequest(frame));
            break;
        case kXR_sync:
            out.add(new SyncRequest(frame));
            break;
        case kXR_close:
            out.add(new CloseRequest(frame));
            break;
        case kXR_protocol:
            out.add(new ProtocolRequest(frame));
            break;
        case kXR_rm:
            out.add(new RmRequest(frame));
            break;
        case kXR_rmdir:
            out.add(new RmDirRequest(frame));
            break;
        case kXR_mkdir:
            out.add(new MkDirRequest(frame));
            break;
        case kXR_mv:
            out.add(new MvRequest(frame));
            break;
        case kXR_dirlist:
            out.add(new DirListRequest(frame));
            break;
        case kXR_auth:
            out.add(new AuthenticationRequest(frame));
            break;
        case kXR_endsess:
            out.add(new EndSessionRequest(frame));
            break;
        case kXR_locate :
            out.add(new LocateRequest(frame));
            break;
        case kXR_query:
            out.add(new QueryRequest(frame));
            break;
        case kXR_set:
            out.add(new SetRequest(frame));
            break;
        default:
            out.add(new UnknownRequest(frame));
            break;
        }
    }
}
