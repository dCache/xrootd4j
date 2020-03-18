/**
 * Copyright (C) 2011-2020 dCache.org <support@dcache.org>
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

import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.ProtocolResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;

public class XrootdProtocolRequestHandler extends XrootdRequestHandler
{
    private static final Logger         LOGGER
                    = LoggerFactory.getLogger(XrootdProtocolRequestHandler.class);

    protected            SigningPolicy  signingPolicy;
    protected            TLSSessionInfo tlsSessionInfo;

    public void setSigningPolicy(SigningPolicy signingPolicy)
    {
        this.signingPolicy = signingPolicy;
    }

    public void setTlsSessionInfo(TLSSessionInfo tlsSessionInfo)
    {
        this.tlsSessionInfo = tlsSessionInfo;
    }

    @Override
    protected XrootdResponse<ProtocolRequest> doOnProtocolRequest(ChannelHandlerContext ctx,
                                                                  ProtocolRequest msg)
                    throws XrootdException
    {
        if (tlsSessionInfo == null) {
            throw new XrootdException(kXR_ServerError, "incomplete server "
                            + "information on protocol request");
        }

        LOGGER.debug("doOnProtocolRequest, version {}, expect {}, option {}.",
                    msg.getVersion(), msg.getExpect(), msg.getOption());

        tlsSessionInfo.setLocalTlsActivation(msg.getVersion(),
                                             msg.getOption(),
                                             msg.getExpect());

        if (tlsSessionInfo.serverUsesTls()) {
            boolean isStarted = tlsSessionInfo.serverTransitionedToTLS(kXR_protocol,
                                                                        ctx);
            LOGGER.debug("kXR_protocol, server has now transitioned to tls? {}.",
                         isStarted);
        }

        LOGGER.debug("Sending protocol message with server flags {}, "
                                     + "signing policy {}.",
                     tlsSessionInfo.getLocalServerProtocolFlags(), signingPolicy);

        return new ProtocolResponse(msg,
                                    tlsSessionInfo.getLocalServerProtocolFlags()
                                                  .getFlags(),
                                    signingPolicy);
    }
}
