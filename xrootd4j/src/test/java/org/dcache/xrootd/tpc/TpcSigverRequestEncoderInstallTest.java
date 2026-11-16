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
package org.dcache.xrootd.tpc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import java.util.List;
import java.util.stream.Collectors;
import org.dcache.xrootd.security.SigningPolicy;
import org.junit.Before;
import org.junit.Test;

/**
 * A client may try several authentication protocols on one channel.  Each protocol may install
 * a sigver encoder; the channel must end up with exactly one, the one installed last.
 */
public class TpcSigverRequestEncoderInstallTest {

    private EmbeddedChannel channel;

    @Before
    public void setUp() {
        channel = new EmbeddedChannel();
        channel.pipeline().addLast("encoder", new ChannelOutboundHandlerAdapter());
    }

    @Test
    public void shouldInstallEncoderAfterRequestEncoder() {
        TpcSigverRequestEncoder encoder = newEncoder();

        TpcSigverRequestEncoder.install(channel.pipeline(), encoder);

        assertSame(encoder, channel.pipeline().get(TpcSigverRequestEncoder.NAME));
        List<String> names = handlerNames();
        assertEquals(names.indexOf("encoder") + 1, names.indexOf(TpcSigverRequestEncoder.NAME));
    }

    @Test
    public void shouldReplaceEncoderInstalledByEarlierProtocol() {
        TpcSigverRequestEncoder first = newEncoder();
        TpcSigverRequestEncoder second = newEncoder();

        TpcSigverRequestEncoder.install(channel.pipeline(), first);
        TpcSigverRequestEncoder.install(channel.pipeline(), second);

        assertSame(second, channel.pipeline().get(TpcSigverRequestEncoder.NAME));
        assertEquals(1, handlerNames().stream()
              .filter(TpcSigverRequestEncoder.NAME::equals).count());
    }

    private List<String> handlerNames() {
        return channel.pipeline().names().stream().collect(Collectors.toList());
    }

    private static TpcSigverRequestEncoder newEncoder() {
        return new TpcSigverRequestEncoder(null, new SigningPolicy());
    }
}
