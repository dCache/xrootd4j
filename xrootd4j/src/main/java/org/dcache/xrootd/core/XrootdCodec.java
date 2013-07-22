/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.HandshakeRequest;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.UnknownRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A FrameDecoder decoding xrootd frames into AbstractRequestMessage
 * objects.
 */
public class XrootdCodec extends ByteToMessageCodec<AbstractResponseMessage>
{
    private static final Logger LOGGER =
        LoggerFactory.getLogger(XrootdCodec.class);

    private boolean gotHandshake = false;

    @Override
    protected Object decode(ChannelHandlerContext ctx, ByteBuf in) throws Exception
    {
        int readable = in.readableBytes();

        /* The first 20 bytes form a handshake.
         */
        if (!gotHandshake) {
            if (readable < CLIENT_HANDSHAKE_LEN) {
                return null;
            }
            gotHandshake = true;

            return new HandshakeRequest(in.readSlice(CLIENT_HANDSHAKE_LEN));
        }

        /* All other requests have a common framing format with a
         * fixed length header.
         */
        if (readable < CLIENT_REQUEST_LEN) {
            return null;
        }

        int pos = in.readerIndex();
        int headerFrameLength = in.getInt(pos + 20);

        if (headerFrameLength < 0) {
            LOGGER.error("Received illegal frame length in xrootd header: {}."
                    + " Closing channel.", headerFrameLength);
            ctx.channel().close();
            return null;
        }

        int length = CLIENT_REQUEST_LEN + headerFrameLength;

        if (readable < length) {
            return null;
        }

        ByteBuf frame = in.readBytes(length);
        int requestID = frame.getUnsignedShort(2);

        switch (requestID) {
        case kXR_login:
            return new LoginRequest(frame);
        case kXR_prepare:
            return new PrepareRequest(frame);
        case kXR_open:
            return new OpenRequest(frame);
        case kXR_stat:
            return new StatRequest(frame);
        case kXR_statx:
            return new StatxRequest(frame);
        case kXR_read:
            return new ReadRequest(frame);
        case kXR_readv:
            return new ReadVRequest(frame);
        case kXR_write:
            return new WriteRequest(frame);
        case kXR_sync:
            return new SyncRequest(frame);
        case kXR_close:
            return new CloseRequest(frame);
        case kXR_protocol:
            return new ProtocolRequest(frame);
        case kXR_rm:
            return new RmRequest(frame);
        case kXR_rmdir:
            return new RmDirRequest(frame);
        case kXR_mkdir:
            return new MkDirRequest(frame);
        case kXR_mv:
            return new MvRequest(frame);
        case kXR_dirlist:
            return new DirListRequest(frame);
        case kXR_auth:
            return new AuthenticationRequest(frame);
        case kXR_endsess:
            return new EndSessionRequest(frame);
        default:
            return new UnknownRequest(frame);
        }
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, AbstractResponseMessage msg, ByteBuf out)
            throws Exception
    {
        ByteBuf buffer = msg.getBuffer();
        buffer.setInt(4, buffer.readableBytes() - 8);
        out.writeBytes(buffer);
    }
}
