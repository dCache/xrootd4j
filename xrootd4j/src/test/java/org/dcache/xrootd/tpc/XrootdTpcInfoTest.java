/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.Map;
import org.dcache.xrootd.tpc.XrootdTpcInfo.ClientRole;
import org.dcache.xrootd.tpc.XrootdTpcInfo.ServerRole;
import org.dcache.xrootd.util.OpaqueStringParser;
import org.dcache.xrootd.util.ParseException;
import org.junit.Test;

public class XrootdTpcInfoTest {

    private XrootdTpcInfo info;

    @Test
    public void shouldIdentifyClientRequestToSource() throws Exception {
        givenOpaque("?tpc.dst=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.5 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_SOURCE));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_ORCHESTRATOR));
        assertTrue(info.isTpcRequest());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotProvideSourceUrlForClientSourceRequest() throws Exception {
        givenOpaque("?tpc.dst=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.5 of spec.

        info.getSourceURL("/path/on/destination/for/file");
    }

    @Test
    public void shouldIdentifyClientRequestToDestination() throws Exception {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_DESTINATION));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_ORCHESTRATOR));
        assertTrue(info.isTpcRequest());
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnly() throws Exception {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy"); // From section 2.3 of spec.

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(),
              equalTo("xroot://hostname/path/on/destination/for/file"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnlyWithAbsoluteLfn()
          throws Exception {
        givenOpaque(
              "?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.lfn=/path/on/source/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/source/for/source"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostOnlyWithRelativeLfn()
          throws Exception {
        givenOpaque(
              "?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.lfn=path/on/source/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("xroot://hostname/path/on/source/for/source"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndPort() throws Exception {
        givenOpaque("?tpc.src=hostname:1234&tpc.key=token&tpc.stage=copy");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(),
              equalTo("xroot://hostname:1234/path/on/destination/for/file"));
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndDefaultPort()
          throws Exception {
        givenOpaque("?tpc.src=hostname:1094&tpc.key=token&tpc.stage=copy");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(),
              equalTo("xroot://hostname/path/on/destination/for/file"));
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotProvideSourceUrlForDestinationRequestToSource() throws Exception {
        givenOpaque(
              "?tpc.key=token&tpc.org=user@hostname&tpc.stage=copy"); // From section 3 of spec.

        info.getSourceURL("/path/on/destination/for/file");
    }

    @Test
    public void shouldIdentifyDestinationRequestToSource() throws Exception {
        givenOpaque(
              "?tpc.key=token&tpc.org=user@hostname&tpc.stage=copy"); // From section 3 of spec.

        assertThat(info.getServerRole(), equalTo(ServerRole.TPC_SOURCE));
        assertThat(info.getClientRole(), equalTo(ClientRole.TPC_DESTINATION));
        assertTrue(info.isTpcRequest());
    }

    @Test
    public void shouldProvideSourceUrlForClientDestinationRequestHostAndSourceProtocol()
          throws Exception {
        givenOpaque(
              "?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=https&tpc.lfn=path/for/source");

        URI source = info.getSourceURL("/path/on/destination/for/file");

        assertThat(source.toASCIIString(), equalTo("https://hostname/path/for/source"));
    }

    @Test
    public void shouldNotIdentifyMissingSprAsTls() throws Exception {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy");

        assertFalse(info.isTls());
    }

    @Test
    public void shouldNotIdentifySprXrootAsTls() throws Exception {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=xroot");

        assertFalse(info.isTls());
    }

    @Test
    public void shouldIdentifySprXrootsAsTls() throws Exception {
        givenOpaque("?tpc.src=hostname&tpc.key=token&tpc.stage=copy&tpc.spr=xroots");

        assertTrue(info.isTls());
    }

    @Test
    public void shouldFindAliceTypeTokenFromSCGI() throws Exception {
        /*
         * -----BEGIN SEALED CIPHER-----
         * ..
         * .. (Base64-encoded cipher)
         * ..
         * -----END SEALED CIPHER-----
         * -----BEGIN SEALED ENVELOPE-----
         * ..
         * .. (Base64-encoded envelope)
         * ..
         * -----END SEALED ENVELOPE-----
         */
        String authz = new StringBuilder()
              .append("-----BEGIN SEALED CIPHER-----")
              .append("\n")
              .append("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9")
              .append(".eyJ2ZXIiOiJzY2l0b2tlbjoyLjAiLCJhdWQiOiJodHRwczovL2RlbW8uc2")
              .append("NpdG9rZW5zLm9yZyIsImlzcyI6Imh0dHBzOi8vZGVtby5zY2l0b2tlbnMub3")
              .append("JnIiwiaWF0IjoxNjEzNTAwMjM5LCJuYmYiOjE2MTM1MDAyMzksImp0aSI6Im")
              .append("U3NzY4NTAzLWIxMzUtNDhhOC04YTc5LTUwMThlZDI2YzBjZiIsInNjb3BlI")
              .append("\n")
              .append("-----END SEALED CIPHER-----")
              .append("\n")
              .append("-----BEGIN SEALED ENVELOPE-----")
              .append("\n")
              .append("joicmVhZDovcG5mcy9mcy91c3IvdGVzdC9hcm9zc2kvdm9sYXRpbGUgd3Jpd")
              .append("GU6L3BuZnMvZnMvdXNyL3Rlc3QvYXJvc3NpL3ZvbGF0aWxlIiwiZXhwIjox")
              .append("NjEzNzAwMDAwfQ.Vqa0WDYOPiPTM-RtV6r0HMm0SkdGoRo5p2jtiHLzJK-")
              .append("nN-Z67xc_A6t7mtGo5SxcIEu65XWlUVIUOCM5_keIcye4HNcI1OGaXOoIm")
              .append("iXP_pBOiIgk_VWcCjxUDhyYnguLGOP2HCeitblJnyQ88IcNCQ0ayQmqS4bz6")
              .append("EQjiXdhHJDcsi3wGhSGrvO4rJR-B2nR4HA5m7I8cUF9Z07FxJA7eGdNN_x")
              .append("DcVjWgOG2UeG9fIypGWCx_UU7tQPJdDt73JZCQzgP9RBvnnQE8wp0rHNkUSK")
              .append("_ov89itVf74QmGw_1D88tew9Xq45JjPb1rS1z7L1XMWsqTenZeIMe98ISiyxVDw")
              .append("\n")
              .append("-----END SEALED ENVELOPE-----")
              .toString();
        StringBuilder sb = new StringBuilder("?tpc.src=hostname");
        sb.append("&authz=").append(authz)
              .append("&tpc.key=token&tpc.stage=copy")
              .append("&tpc.scgi=authz=")
              .append(authz)
              .append("\t")
              .append("tpc.stage=placement")
              .append("&tpc.spr=xroots");
        givenOpaque(sb.toString());

        assertEquals("Token does not match.",
              authz, info.getSourceToken());
    }

    @Test
    public void shouldFindSourceAuthzFromSCGI() throws Exception {
        String authz = new StringBuilder()
              .append("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9")
              .append(".eyJ2ZXIiOiJzY2l0b2tlbjoyLjAiLCJhdWQiOiJodHRwczovL2RlbW8uc2")
              .append("NpdG9rZW5zLm9yZyIsImlzcyI6Imh0dHBzOi8vZGVtby5zY2l0b2tlbnMub3")
              .append("JnIiwiaWF0IjoxNjEzNTAwMjM5LCJuYmYiOjE2MTM1MDAyMzksImp0aSI6Im")
              .append("U3NzY4NTAzLWIxMzUtNDhhOC04YTc5LTUwMThlZDI2YzBjZiIsInNjb3BlI")
              .append("joicmVhZDovcG5mcy9mcy91c3IvdGVzdC9hcm9zc2kvdm9sYXRpbGUgd3Jpd")
              .append("GU6L3BuZnMvZnMvdXNyL3Rlc3QvYXJvc3NpL3ZvbGF0aWxlIiwiZXhwIjox")
              .append("NjEzNzAwMDAwfQ.Vqa0WDYOPiPTM-RtV6r0HMm0SkdGoRo5p2jtiHLzJK-")
              .append("nN-Z67xc_A6t7mtGo5SxcIEu65XWlUVIUOCM5_keIcye4HNcI1OGaXOoIm")
              .append("iXP_pBOiIgk_VWcCjxUDhyYnguLGOP2HCeitblJnyQ88IcNCQ0ayQmqS4bz6")
              .append("EQjiXdhHJDcsi3wGhSGrvO4rJR-B2nR4HA5m7I8cUF9Z07FxJA7eGdNN_x")
              .append("DcVjWgOG2UeG9fIypGWCx_UU7tQPJdDt73JZCQzgP9RBvnnQE8wp0rHNkUSK")
              .append("_ov89itVf74QmGw_1D88tew9Xq45JjPb1rS1z7L1XMWsqTenZeIMe98ISiyxVDw")
              .toString();
        StringBuilder sb = new StringBuilder("?tpc.src=hostname");
        sb.append("&authz=").append(authz)
              .append("&tpc.key=token&tpc.stage=copy")
              .append("&tpc.scgi=authz=")
              .append(authz)
              .append("\t")
              .append("tpc.stage=placement")
              .append("&tpc.spr=xroots");
        givenOpaque(sb.toString());

        assertEquals("Token does not match.",
              authz, info.getSourceToken());
    }

    @Test
    public void shouldNotFindSourceAuthzFromSCGI() throws Exception {
        String authz = new StringBuilder()
              .append("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9")
              .append(".eyJ2ZXIiOiJzY2l0b2tlbjoyLjAiLCJhdWQiOiJodHRwczovL2RlbW8uc2")
              .append("NpdG9rZW5zLm9yZyIsImlzcyI6Imh0dHBzOi8vZGVtby5zY2l0b2tlbnMub3")
              .append("JnIiwiaWF0IjoxNjEzNTAwMjM5LCJuYmYiOjE2MTM1MDAyMzksImp0aSI6Im")
              .append("U3NzY4NTAzLWIxMzUtNDhhOC04YTc5LTUwMThlZDI2YzBjZiIsInNjb3BlI")
              .append("joicmVhZDovcG5mcy9mcy91c3IvdGVzdC9hcm9zc2kvdm9sYXRpbGUgd3Jpd")
              .append("GU6L3BuZnMvZnMvdXNyL3Rlc3QvYXJvc3NpL3ZvbGF0aWxlIiwiZXhwIjox")
              .append("NjEzNzAwMDAwfQ.Vqa0WDYOPiPTM-RtV6r0HMm0SkdGoRo5p2jtiHLzJK-")
              .append("nN-Z67xc_A6t7mtGo5SxcIEu65XWlUVIUOCM5_keIcye4HNcI1OGaXOoIm")
              .append("iXP_pBOiIgk_VWcCjxUDhyYnguLGOP2HCeitblJnyQ88IcNCQ0ayQmqS4bz6")
              .append("EQjiXdhHJDcsi3wGhSGrvO4rJR-B2nR4HA5m7I8cUF9Z07FxJA7eGdNN_x")
              .append("DcVjWgOG2UeG9fIypGWCx_UU7tQPJdDt73JZCQzgP9RBvnnQE8wp0rHNkUSK")
              .append("_ov89itVf74QmGw_1D88tew9Xq45JjPb1rS1z7L1XMWsqTenZeIMe98ISiyxVDw")
              .toString();
        StringBuilder sb = new StringBuilder("?tpc.src=hostname");
        sb.append("&authz=").append(authz)
              .append("&tpc.key=token&tpc.stage=copy")
              .append("&tpc.scgi=tpc.stage=placement")
              .append("&tpc.spr=xroots");
        givenOpaque(sb.toString());

        assertNull("Token was not null.", info.getSourceToken());
    }

    public void givenOpaque(String opaque) throws ParseException {
        Map<String, String> metadata = OpaqueStringParser.getOpaqueMap(opaque);
        info = new XrootdTpcInfo(metadata);
    }
}
