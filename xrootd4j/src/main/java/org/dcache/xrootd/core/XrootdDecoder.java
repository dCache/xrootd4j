/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * A FrameDecoder decoding xrootd frames into AbstractRequestMessage
 * objects.
 */
public class XrootdDecoder extends AbstractXrootdDecoder
{
    /**
     * This method is shared by several authn protocols.
     */
    public static String readAscii(ByteBuf buffer, int length)
    {
        String ascii = buffer.toString(buffer.readerIndex(), length, US_ASCII)
                                .trim();
        /* toString does not advance the index */
        buffer.readerIndex(buffer.readerIndex() + length);
        return ascii;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
    {
        int length = verifyMessageLength(in);

        if (length < 0) {
            ctx.channel().close();
            return;
        }

        if (length == 0) {
            return;
        }

        out.add(getRequest(in.readSlice(length)));
    }
}
