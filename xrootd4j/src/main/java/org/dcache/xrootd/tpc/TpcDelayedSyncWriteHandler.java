/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc;

import io.netty.channel.ChannelHandlerContext;
import java.io.IOException;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundRedirectResponse;

/**
 * Defines the two tasks involved in third-party destination transfers:
 *    writing the bytes read by the client, and notifying the originating
 *    (user) client when the transfer succeeds or fails, via an asynchronous
 *    response to a sync request.</p>
 */
public interface TpcDelayedSyncWriteHandler {

    void fireDelayedSync(int result, String error);

    void write(InboundReadResponse response) throws IOException;

    /**
     * Needs to be implemented by the caller (outside the pipeline).
     *    The client may as a consequence need to be discarded and a new one
     *    constructed with the new contact string.</p>
     */
    void redirect(ChannelHandlerContext ctx,
          InboundRedirectResponse response) throws XrootdException;
}
