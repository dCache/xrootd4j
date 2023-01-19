/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import static java.nio.charset.StandardCharsets.US_ASCII;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Downstream ChannelHandler encoding XrootdResponse objects
 * into ByteBuf objects.
 */
@Sharable
public class XrootdEncoder extends ChannelOutboundHandlerAdapter {

    protected static final Logger LOGGER = LoggerFactory.getLogger(XrootdEncoder.class);

    /**
     * Write exactly {@literal length} bytes to {@literal out}.
     * As many bytes are taken from {@literal data} as possible.
     * If {@literal data} is too short then the additional bytes are zero.
     *
     * @param data  to write
     * @param out   buffer to write to
     * @param length up to this number of bytes
     */
    public static void writeZeroPad(String data, ByteBuf out, int length) {
        byte[] bytes = data.getBytes(US_ASCII);
        int len = Math.min(bytes.length, length);
        out.writeBytes(bytes, 0, len);
        if (len < length) {
            out.writeZero(length - len);
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
          throws Exception {
        if (msg instanceof XrootdResponse<?>) {
            XrootdResponse<?> response = (XrootdResponse<?>) msg;
            if (response instanceof OkResponse) {
                XrootdRequest request = response.getRequest();
                /*
                 *  In the case of segmented write requests, only send back a response
                 *  to the client when the full frame size has been handled.
                 */
                if (request instanceof WriteRequest && !((WriteRequest)request).isComplete()) {
                    LOGGER.trace("incomplete write request of length {}; skipping response.",
                          ((WriteRequest)request).getDataLength());
                    return;
                }
            }
            LOGGER.trace("sending response: {} for {}.", response.getStatus(),
                  XrootdProtocol.getClientRequest(response.getRequest().getRequestId()));
            response.writeTo(ctx, promise);
        } else {
            super.write(ctx, msg, promise);
        }
    }
}
