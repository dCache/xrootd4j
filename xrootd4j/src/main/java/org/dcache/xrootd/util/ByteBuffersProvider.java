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
package org.dcache.xrootd.util;

import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufAllocatorMetricProvider;
import io.netty.util.ReferenceCounted;
import java.nio.ByteBuffer;
import java.util.Locale;
import org.slf4j.Logger;

/**
 * This interface pulls out the two methods necessary to support the write. </p>
 *
 * The reason for doing so is to avoid an additional buffer copy
 *    in translating a ThirdParty read request response into a write request.</p>
 */
public interface ByteBuffersProvider extends ReferenceCounted {

    /**
     * For monitoring memory usage by Netty allocators.  This method is best
     * guarded by a conditional checking logger level activation.
     *
     * @param when info concerning the site of the call
     * @param allocator e.g., from the context
     * @param logger to use
     * @param level to log at (only supports "INFO", "DEBUG", "TRACE")
     */
    static void logMetrics(String when, ByteBufAllocator allocator, Logger logger, String level) {
        if (allocator instanceof ByteBufAllocatorMetricProvider) {
            ByteBufAllocatorMetricProvider provider = (ByteBufAllocatorMetricProvider) allocator;
            switch (level.toUpperCase(Locale.ROOT)) {
                case "INFO":
                    logger.info("allocator {}.{} –– {}: {}", allocator.getClass().getSimpleName(),
                          allocator.hashCode(), when, provider.metric());
                    break;
                case "DEBUG":
                    logger.debug("allocator {}.{} –– {}: {}", allocator.getClass().getSimpleName(),
                          allocator.hashCode(), when, provider.metric());
                    break;
                case "TRACE":
                    logger.trace("allocator {}.{} –– {}: {}", allocator.getClass().getSimpleName(),
                          allocator.hashCode(), when, provider.metric());
                    break;
            }
        }
    }

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
