/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi.pre49;

import eu.emi.security.authn.x509.X509Credential;
import io.netty.channel.ChannelHandlerContext;

import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.GSIClientRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.GSICredentialManager;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_puk;

public class GSIPre49ClientRequestHandler extends GSIClientRequestHandler
{
    public GSIPre49ClientRequestHandler(GSICredentialManager credentialManager,
                                        XrootdTpcClient client)
    {
        super(credentialManager, client);
    }

    @Override
    public int getProtocolVersion()
    {
        return PROTO_PRE_DELEGATION;
    }

    public OutboundAuthenticationRequest handleCertStep(InboundAuthenticationResponse response,
                                                        ChannelHandlerContext ctx)
                    throws XrootdException
    {
        return handleCertStep(response,
                              ctx,
                              kXRS_puk,
                              false,
                              Optional.empty(),
                              Optional.empty());
    }

    @Override
    protected X509Credential getClientCredential()
    {
        return credentialManager.getProxy();
    }

    @Override
    protected Optional<Integer> getClientOpts()
    {
        return Optional.empty();
    }

    @Override
    protected String getSyncCipherMode() {
        return SYNC_CIPHER_MODE_PADDED;
    }

    @Override
    protected void handleAuthenticationError(InboundErrorResponse response)
                    throws XrootdException {
        throw new XrootdException(response.getError(),
                                  response.getErrorMessage());
    }

    @Override
    protected void loadClientCredential()
    {
        /*
         *  NOP
         *
         *  If the credentials failed to load at initialization,
         *  the issue will soon be discovered
         *  when GSI TPC fails.
         */
    }

    @Override
    protected boolean usePadded()
    {
        return false;
    }
}
