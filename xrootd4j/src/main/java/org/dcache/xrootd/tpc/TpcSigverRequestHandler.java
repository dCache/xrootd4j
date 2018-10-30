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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.BufferEncrypter;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdOutboundRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundSigverRequest;
import org.dcache.xrootd.tpc.protocol.messages.XrootdOutboundRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_signIgnore;

/**
 * <p>Checks to see if the protocol security context requires
 *    the particular message to be preceded by a signing verification
 *    request, and returns one if so.</p>
 *
 * <p>If the encrypter is <code>null</code>, unencrypted hashes are sent.</p>
 */
public class TpcSigverRequestHandler {
    protected final BufferEncrypter         encrypter;
    protected final XrootdTpcClient         client;
    protected long seqno;

    public TpcSigverRequestHandler(BufferEncrypter encrypter, XrootdTpcClient client)
    {
        this.encrypter = encrypter;
        this.client = client;
    }

    /**
     * @param request to be signed
     * @return request sent before the main request with hash to be checked.
     */
    public OutboundSigverRequest createSigverRequest(ChannelHandlerContext ctx,
                                                     XrootdOutboundRequest request)
                    throws XrootdException
    {
        if (!(request instanceof AbstractXrootdOutboundRequest)) {
            return null;
        }

        AbstractXrootdOutboundRequest abstractRequest
                        = (AbstractXrootdOutboundRequest)request;

        Map<Integer, Integer> overrides = client.getOverrides();
        Integer override = overrides.get(abstractRequest.getRequestId());

        if (!abstractRequest.isSigned(client.getSeclvl(),
                                      override == null ? kXR_signIgnore : override)) {
            return null;
        }

        ++seqno;

        try {
            OutboundSigverRequest sigverRequest = new OutboundSigverRequest(seqno,
                                                                            abstractRequest,
                                                                            ctx);
            if (encrypter != null) {
                sigverRequest.encrypt(encrypter);
            }

            return sigverRequest;
        } catch (NoSuchAlgorithmException |
                        InvalidKeyException |
                        InvalidAlgorithmParameterException |
                        NoSuchPaddingException |
                        BadPaddingException |
                        NoSuchProviderException |
                        IllegalBlockSizeException e) {
            throw new XrootdException(kXR_ServerError, e.getMessage());
        }
    }
}
