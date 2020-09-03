/**
 * Copyright (C) 2020 dCache.org <support@dcache.org>
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

    @Test
    public void shouldIdentifyClientRequestToDestination() throws Exception
    {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_DESTINATION));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_ORCHESTRATOR));
        assertTrue(info.isTpcRequest());
    }

    @Test
    public void shouldIdentifyDestinationRequestToSource() throws Exception
    {
        givenOpaque("?tpc.key=token&tpc.org=user@hostname&tpc.stage=copy"); // From section 3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_SOURCE));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_DESTINATION));
        assertTrue(info.isTpcRequest());
    }

    public void givenOpaque(String opaque) throws ParseException
    {
        Map<String,String> metadata = OpaqueStringParser.getOpaqueMap(opaque);
        info = new XrootdTpcInfo(metadata);
    }
}
