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
package org.dcache.xrootd.tpc;

import org.junit.Test;

import java.net.URI;
import java.util.Map;

import org.dcache.xrootd.tpc.XrootdTpcInfo.ClientRole;
import org.dcache.xrootd.tpc.XrootdTpcInfo.ServerRole;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;

public class XrootdTpcInfoTest
{
    private XrootdTpcInfo info;

    @Test
    public void shouldIdentifyClientRequestToSource() throws Exception
    {
        givenOpaque("?tpc.dst=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.5 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_SOURCE));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_ORCHESTRATOR));
        assertTrue(info.isTpcRequest());
    }

    @Test(expected=IllegalStateException.class)
    public void shouldNotProvideSourceUrlForClientSourceRequest() throws Exception
    {
        givenOpaque("?tpc.dst=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.5 of spec.

        info.getSourceURL("/path/on/destination/for/file");
    }

    @Test
    public void shouldIdentifyClientRequestToDestination() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_DESTINATION));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_ORCHESTRATOR));
        assertTrue(info.isTpcRequest());
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnly() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.3 of spec.

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/destination/for/file"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnlyWithAbsoluteLfn() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.lfn=/path/on/source/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/source/for/source"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnlyWithRelativeLfn() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.lfn=path/on/source/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/source/for/source"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndPort() throws Exception
    {
        givenOpaque("?tpc.src=hostname:1234&tpc.key=token&tpc.stage=copy");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname:1234/path/on/destination/for/file"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndDefaultPort() throws Exception
    {
        givenOpaque("?tpc.src=hostname:1094&tpc.key=token&tpc.stage=copy");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/destination/for/file"));
    }

    @Test(expected=IllegalStateException.class)
    public void shouldNotProvideSourceUrlForDestinationRequestToSource() throws Exception
    {
        givenOpaque("?tpc.key=token&tpc.org=user@hostname&tpc.stage=copy"); // From section 3 of spec.

        info.getSourceURL("/path/on/destination/for/file");
    }

    @Test
    public void shouldIdentifyDestinationRequestToSource() throws Exception
    {
        givenOpaque("?tpc.key=token&tpc.org=user@hostname&tpc.stage=copy"); // From section 3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_SOURCE));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_DESTINATION));
        assertTrue(info.isTpcRequest());
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndSourceProtocol() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=https&tpc.lfn=path/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("https://hostname/path/for/source"));
    }

    @Test
    public void shouldNotIdentifyMissingSprAsTls() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy");

        assertFalse(info.isTls());
    }

    @Test
    public void shouldNotIdentifySprXrootAsTls() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=xroot");

        assertFalse(info.isTls());
    }

    @Test
    public void shouldIdentifySprXrootsAsTls() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=xroots");

        assertTrue(info.isTls());
    }

    public void givenOpaque(String opaque) throws ParseException
    {
        Map<String,String> metadata = OpaqueStringParser.getOpaqueMap(opaque);
        info = new XrootdTpcInfo(metadata);
    }
}
