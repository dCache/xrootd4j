/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.util;

import io.netty.util.ReferenceCounted;

import java.nio.ByteBuffer;

/**
 * <p>This interface pulls out the two methods necessary to support the write. </p>
 *
 * <p>The reason for doing so is to avoid an additional buffer copy
 *    in translating a ThirdParty read request response into a write request.</p>
 */
public interface ByteBuffersProvider extends ReferenceCounted {
    /**
     * @return NIO buffer array produced from the Netty ByteBuf.
     */
    ByteBuffer[] toByteBuffers();

    /**
     * @return the current offset to the buffer or channel receiving the
     *          written bytes.
     */
    long getWriteOffset();
}
