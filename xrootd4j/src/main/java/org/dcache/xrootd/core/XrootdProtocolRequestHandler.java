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
package org.dcache.xrootd.core;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_TLSRequired;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;

import io.netty.channel.ChannelHandlerContext;
import java.util.Map;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.ProtocolResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XrootdProtocolRequestHandler extends XrootdRequestHandler {

    private static final Logger LOGGER
          = LoggerFactory.getLogger(XrootdProtocolRequestHandler.class);

    protected SigningPolicy signingPolicy;
    protected TLSSessionInfo tlsSessionInfo;

    public void setSigningPolicy(SigningPolicy signingPolicy) {
        this.signingPolicy = signingPolicy;
    }

    public void setTlsSessionInfo(TLSSessionInfo tlsSessionInfo) {
        this.tlsSessionInfo = tlsSessionInfo;
    }

    @Override
    protected XrootdResponse<ProtocolRequest> doOnProtocolRequest(ChannelHandlerContext ctx,
          ProtocolRequest msg)
          throws XrootdException {
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
            /*
             *  If there is/will be TLS, turn off signing by overriding
             *  local settings.
             */
            signingPolicy = SigningPolicy.OFF;
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

    /**
     * This is a supplementary check to make sure that non-TLS-capable
     * clients (i.e., pre-v5) are not allowed to connect if they intend
     * to do TPC and the "requiresTLSForTPC" is set on the destination server.
     * <p/>
     *
     * We also check here to make sure that the client has connected to
     * the destination server with 'xroots' if the destination server
     * requires TLS for TPC.
     *
     * @throws XrootdException
     */
    protected void enforceClientTlsIfDestinationRequiresItForTpc(Map<String, String> opaque)
          throws XrootdException {
        if (!opaque.containsKey("tpc.org") && !opaque.containsKey("tpc.src")) {
            LOGGER.debug("server is not TPC destination; no TLS TPC check.");
            return;
        }

        String spr = opaque.get("tpc.spr");
        String tpr = opaque.get("tpc.tpr");

        LOGGER.debug("server requires tls for tpc {}; "
                    + "incoming client is TLS capable {}; "
                    + "tpc.spr {}, tpc.tpr {}.",
              tlsSessionInfo.getLocalServerProtocolFlags()
                    .requiresTLSForTPC(),
              tlsSessionInfo.isIncomingClientTLSCapable(),
              spr, tpr);
        /*
         *  Fail if destination server requires TLS for TPC and either
         *  (a) the client is not TLS capable, or
         *  (b) the client has not connected to the destination using xroots.
         *
         *  The latter check is to make sure that any bearer tokens passed
         *  to the destination are protected for TPC as well.
         */
        if (tlsSessionInfo.getLocalServerProtocolFlags().requiresTLSForTPC()) {
            if (!tlsSessionInfo.isIncomingClientTLSCapable()) {
                throw new XrootdException(kXR_TLSRequired,
                      "Server accepts only secure connections for TPC.");
            }

            if (!"xroots".equals(tpr)) {
                throw new XrootdException(kXR_TLSRequired,
                      "Wrong protocol expressed for TPC destination.");
            }
        }
    }
}
