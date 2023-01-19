/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class LoginRequestTest extends DecoderTest<LoginRequest>
{
    public LoginRequestTest()
    {
        super(LoginRequest::new);
    }

    @Test
    public void shouldDecodeEmptyToken()
    {
        given(encodedRequest()
                .withShort(1)    // streamid
                .withShort(3007) // kXR_login
                .withInt(2) // pid
                .withFixedSizeString(8, "USERNAME", US_ASCII)
                .withZeros(1) // reserved
                .withByte(3) // zone
                .withByte(4) // capver
                .withByte(0) // role
                .withString("", US_ASCII)); // token

        LoginRequest decoded = whenDecoded();

        assertThat(decoded.getStreamId(), is(equalTo(1)));
        assertThat(decoded.getPID(), is(equalTo(2)));
        assertThat(decoded.getUserName(), is(equalTo("USERNAME")));
        assertThat(decoded.getClientProtocolVersion(), is(equalTo(4)));
        assertThat(decoded.supportsAsyn(), is(equalTo(false)));
        assertThat(decoded.isAdmin(), is(equalTo(false)));
        assertThat(decoded.getToken(), isEmptyString());
    }

    @Test
    public void shouldDecodeAdminWithAsync()
    {
        given(encodedRequest()
                .withShort(1)    // streamid
                .withShort(3007) // kXR_login
                .withInt(2) // pid
                .withFixedSizeString(8, "USERNAME", US_ASCII)
                .withZeros(1) // reserved
                .withByte(3) // zone
                .withByte(0x84) // capver
                .withByte(1) // role
                .withString("", US_ASCII)); // token

        LoginRequest decoded = whenDecoded();

        assertThat(decoded.getStreamId(), is(equalTo(1)));
        assertThat(decoded.getPID(), is(equalTo(2)));
        assertThat(decoded.getUserName(), is(equalTo("USERNAME")));
        assertThat(decoded.getClientProtocolVersion(), is(equalTo(4)));
        assertThat(decoded.supportsAsyn(), is(equalTo(true)));
        assertThat(decoded.isAdmin(), is(equalTo(true)));
        assertThat(decoded.getToken(), isEmptyString());
    }

    @Test
    public void shouldDecodeWithToken()
    {
        given(encodedRequest()
                .withShort(1)    // streamid
                .withShort(3007) // kXR_login
                .withInt(2) // pid
                .withFixedSizeString(8, "USERNAME", US_ASCII)
                .withZeros(1) // reserved
                .withByte(3) // zone
                .withByte(4) // capver
                .withByte(0) // role
                .withString("&P=gsi ,v=foo", US_ASCII));

        LoginRequest decoded = whenDecoded();

        assertThat(decoded.getStreamId(), is(equalTo(1)));
        assertThat(decoded.getPID(), is(equalTo(2)));
        assertThat(decoded.getUserName(), is(equalTo("USERNAME")));
        assertThat(decoded.getClientProtocolVersion(), is(equalTo(4)));
        assertThat(decoded.supportsAsyn(), is(equalTo(false)));
        assertThat(decoded.isAdmin(), is(equalTo(false)));
        assertThat(decoded.getToken(), is(equalTo("&P=gsi ,v=foo")));
    }
}
