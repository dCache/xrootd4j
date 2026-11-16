/**
 * Copyright (C) 2011-2026 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.ztn;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.security.XrootdSecurityProtocol;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.junit.Test;

public class ZTNClientAuthenticationHandlerTest {

    /**
     * Without a token, ztn fails and the client falls back to the next protocol on the same
     * channel.  The failed attempt must not leave a sigver encoder in the pipeline.
     */
    @Test
    public void shouldNotInstallSigverEncoderWhenNoTokenIsAvailable() {
        XrootdTpcInfo info = mock(XrootdTpcInfo.class);
        given(info.getSourceToken()).willReturn(null);
        XrootdTpcClient client = mock(XrootdTpcClient.class);
        given(client.getInfo()).willReturn(info);
        given(client.getSigningPolicy()).willReturn(
              new SigningPolicy(XrootdSecurityProtocol.kXR_secCompatible, false));
        given(client.getTlsSessionInfo()).willReturn(mock(TLSSessionInfo.class));

        ZTNClientAuthenticationHandler handler = new ZTNClientAuthenticationHandler();
        handler.setClient(client);
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline().addLast("encoder", new ChannelOutboundHandlerAdapter());
        channel.pipeline().addLast("ztn", handler);
        ChannelHandlerContext ctx = channel.pipeline().context("ztn");

        try {
            handler.sendAuthenticationRequest(ctx);
            fail("expected failure without a token");
        } catch (XrootdException expected) {
        }

        assertNull(channel.pipeline().get(TpcSigverRequestEncoder.NAME));
    }
}
