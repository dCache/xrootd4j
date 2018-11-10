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
package org.dcache.xrootd.tpc;

import io.netty.channel.ChannelHandlerContext;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.BufferEncrypter;
import org.dcache.xrootd.tpc.protocol.messages.OutboundSigverRequest;
import org.dcache.xrootd.tpc.protocol.messages.XrootdOutboundRequest;

/**
 * <p>Wraps method for creating and possibly encrypting signed hash.</p>
 *
 * @param <E> type of object which can encrypt the hash.
 */
public abstract class TpcSigverRequestHandler<E extends BufferEncrypter> {
    protected final E                       encrypter;
    protected final XrootdTpcClient         client;

    protected TpcSigverRequestHandler(E encrypter, XrootdTpcClient client)
    {
        this.encrypter = encrypter;
        this.client = client;
    }

    public abstract OutboundSigverRequest createSigverRequest(ChannelHandlerContext ctx,
                                                              XrootdOutboundRequest request)
        throws XrootdException;
}
