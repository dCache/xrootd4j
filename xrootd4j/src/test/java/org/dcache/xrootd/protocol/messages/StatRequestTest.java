/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import org.junit.Test;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class StatRequestTest extends DecoderTest<StatRequest>
{
    public StatRequestTest()
    {
        super(StatRequest::new);
    }

    @Test
    public void shouldDecodeEmptyPath()
    {
        given(encodedRequest()
                .withShort(1)    // streamid
                .withShort(3017) // kXR_stat
                .withByte(0)     // opts
                .withZeros(11)   // reserved
                .withInt(2)      // fhandle
                .withString("", US_ASCII)); // path

        StatRequest decoded = whenDecoded();

        assertThat(decoded.getStreamId(), is(equalTo(1)));
        assertThat(decoded.getTarget(), is(equalTo(StatRequest.Target.FHANDLE)));
        assertThat(decoded.getFhandle(), is(equalTo(2)));
        assertThat(decoded.getPath(), isEmptyString());
        assertThat(decoded.getOpaque(), isEmptyString());
    }

    @Test
    public void shouldDecodeWithPath()
    {
        given(encodedRequest()
                .withShort(1)    // streamid
                .withShort(3017) // kXR_stat
                .withByte(0)     // opts
                .withZeros(11)   // reserved
                .withInt(2)      // fhandle
                .withString("my-file.dat", US_ASCII)); // path

        StatRequest decoded = whenDecoded();

        assertThat(decoded.getStreamId(), is(equalTo(1)));
        assertThat(decoded.getTarget(), is(equalTo(StatRequest.Target.PATH)));
        assertThat(decoded.getFhandle(), is(equalTo(2)));
        assertThat(decoded.getPath(), is(equalTo("my-file.dat")));
        assertThat(decoded.getOpaque(), isEmptyString());
    }
}
