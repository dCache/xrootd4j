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
package org.dcache.xrootd.plugins.authn.gsi;

import static org.junit.Assert.assertEquals;

import org.dcache.xrootd.core.XrootdException;
import org.junit.Test;

/**
 * Selection of the message digest and cipher offered by the peer during GSI authentication.
 */
public class AlgorithmNegotiationTest {

    private static class Handler extends GSIRequestHandler {

        Handler() {
            super(null);
        }

        @Override
        public int getProtocolVersion() {
            return PROTOCOL_VERSION;
        }

        @Override
        protected String getSyncCipherMode() {
            return SYNC_CIPHER_MODE_PADDED;
        }
    }

    private final Handler handler = new Handler();

    @Test
    public void shouldAcceptSha256OnlyAsOfferedByXrootdDefault() throws Exception {
        assertEquals("sha256", handler.validateDigests(new String[]{"sha256"}));
    }

    @Test
    public void shouldKeepAcceptingSha1() throws Exception {
        assertEquals("sha1", handler.validateDigests(new String[]{"sha1"}));
    }

    @Test
    public void shouldSelectFirstSupportedDigestInPeerOrder() throws Exception {
        assertEquals("sha256", handler.validateDigests(new String[]{"sha512", "sha256", "sha1"}));
    }

    @Test(expected = XrootdException.class)
    public void shouldRejectUnsupportedDigests() throws Exception {
        handler.validateDigests(new String[]{"sha512", "sha3-256"});
    }

    @Test(expected = XrootdException.class)
    public void shouldNotAcceptPartOfASupportedDigestName() throws Exception {
        handler.validateDigests(new String[]{"sha", "md", "1:md"});
    }

    @Test
    public void shouldOfferSha256First() {
        assertEquals("sha256", GSIRequestHandler.SUPPORTED_DIGESTS.split(":")[0]);
    }

    @Test
    public void shouldAcceptSupportedCipherWithIvLength() throws Exception {
        assertEquals("aes-128-cbc#16",
              handler.validateCiphers(new String[]{"bf-cbc", "aes-128-cbc#16"}));
    }

    @Test(expected = XrootdException.class)
    public void shouldNotAcceptPartOfASupportedCipherName() throws Exception {
        handler.validateCiphers(new String[]{"aes", "aes-128"});
    }
}
