/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

public abstract class GSIClientRequestHandler extends GSIRequestHandler
{
    protected static Logger LOGGER
                    = LoggerFactory.getLogger(GSIClientRequestHandler.class);

    protected final XrootdTpcClient client;

    protected GSIClientRequestHandler(GSICredentialManager credentialManager,
                                      XrootdTpcClient client) {
        super(credentialManager);
        this.client = client;
    }

    public abstract OutboundAuthenticationRequest handleCertReqStep()
                    throws XrootdException;

    public abstract OutboundAuthenticationRequest
        handleCertStep(InboundAuthenticationResponse response,
                       ChannelHandlerContext ctx)
                    throws XrootdException;

    public abstract OutboundAuthenticationRequest
        handleSigPxyStep(InboundAuthenticationResponse response,
                   ChannelHandlerContext ctx)
                    throws XrootdException;
}
