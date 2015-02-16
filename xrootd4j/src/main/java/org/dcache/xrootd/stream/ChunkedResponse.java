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
package org.dcache.xrootd.stream;

import io.netty.buffer.ByteBufAllocator;

import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

/**
 * A large xrootd response which is consumed by {@link ChunkedResponseWriteHandler}.
 */
public interface ChunkedResponse
{

    /**
     * Returns the request this is a response to.
     */
    XrootdRequest getRequest();

    /**
     * Fetches a chunk from the stream.
     *
     * @return the fetched chunk
     */
    XrootdResponse<?> nextChunk(ByteBufAllocator alloc) throws Exception;

    /**
     * Return {@code true} if and only if there is no data left in the stream
     * and the stream has reached its end.
     */
    boolean isEndOfInput() throws Exception;

    /**
     * Releases the resources associated with the stream.
     */
    void close() throws Exception;
}
