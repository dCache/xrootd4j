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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.protocol.messages;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

/**
 * An xrootd response message.
 *
 * Response objects may be reference counted.
 */
public interface XrootdResponse<T extends XrootdRequest>
{
    /**
     * Returns the request this is a response to.
     */
    T getRequest();


    /**
     * The xrootd response status code.
     */
    int getStatus();

    /**
     * Writes the encoded message to the given channel context.
     *
     * Does not flush the channel. This is a destructive call and must at
     * most be called once. Decreases the reference count by {@code 1} and
     * deallocates this object if the reference count reaches {@code 0}.
     */
    void writeTo(ChannelHandlerContext ctx, ChannelPromise promise);
}
