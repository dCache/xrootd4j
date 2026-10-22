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

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_PRE_DELEGATION;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_RTAG_HASH;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_WITH_DELEGATION;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_rtag;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_signed_rtag;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrBadRndmTag;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.EnumMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * GSI random tag handling, see GHSA-4mfc-9mxv-2cf6.
 */
public class RtagTest {

    /**
     * ASN.1 DigestInfo prefix for SHA-256; followed by the 32 byte hash.
     */
    private static final byte[] SHA256_DIGEST_INFO_PREFIX =
          Hex.decode("3031300d060960864801650304020105000420");

    private static final int[] VERSIONS = {
          PROTO_PRE_DELEGATION, PROTO_WITH_DELEGATION, 10600, PROTO_RTAG_HASH
    };

    private static KeyPair keyPair;

    private static class Handler extends GSIRequestHandler {

        private final int version;

        Handler(int version, int remoteVersion) {
            super(null);
            this.version = version;
            setRemoteVersion(remoteVersion);
        }

        @Override
        public int getProtocolVersion() {
            return version;
        }

        @Override
        protected String getSyncCipherMode() {
            return SYNC_CIPHER_MODE_PADDED;
        }
    }

    @BeforeClass
    public static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @Test
    public void shouldGenerateWellFormedChallenge() {
        for (int i = 0; i < 10_000; i++) {
            String challenge = GSIRequestHandler.generateChallengeString();
            assertTrue(challenge,
                  GSIRequestHandler.isValidRtag(challenge.getBytes(US_ASCII)));
        }
    }

    @Test
    public void shouldAcceptWellFormedRtag() {
        assertTrue(GSIRequestHandler.isValidRtag(ascii("aZ09./xY")));
    }

    @Test
    public void shouldRejectMalformedRtag() {
        assertFalse(GSIRequestHandler.isValidRtag(null));
        assertFalse(GSIRequestHandler.isValidRtag(ascii("abcdefg")));
        assertFalse(GSIRequestHandler.isValidRtag(ascii("abcdefghi")));
        assertFalse(GSIRequestHandler.isValidRtag(ascii("abcd-fgh")));
        assertFalse(GSIRequestHandler.isValidRtag(ascii("abcd\0fgh")));
        assertFalse(GSIRequestHandler.isValidRtag(
              new byte[]{'a', 'b', 'c', 'd', (byte) 0xe1, 'f', 'g', 'h'}));
        assertFalse(GSIRequestHandler.isValidRtag(sha256DigestInfo()));
    }

    @Test
    public void shouldMatchXrootdRtagDigest() {
        // printf 'XRD-GSI-RTAG-v1abcdefgh' | sha256sum
        assertArrayEquals(
              Hex.decode("52df717c0c4b2a41dd6f047b8db48cb08677239460bca9d556b34ea7bc6762d0"),
              GSIRequestHandler.rtagDigest(ascii("abcdefgh")));
    }

    @Test
    public void shouldRefuseToSignDigestInfo() throws Exception {
        Handler signer = new Handler(PROTO_RTAG_HASH, PROTO_WITH_DELEGATION);
        signer.rsaSession.initializeForEncryption(keyPair.getPrivate());

        try {
            signer.signRtagChallenge(rtagBuckets(new String(sha256DigestInfo(), ISO_8859_1)));
            fail("DigestInfo was signed");
        } catch (XrootdException e) {
            assertEquals(kGSErrBadRndmTag, e.getError());
        }
    }

    @Test
    public void shouldRefuseToSignMissingRtag() throws Exception {
        Handler signer = new Handler(PROTO_RTAG_HASH, PROTO_RTAG_HASH);
        signer.rsaSession.initializeForEncryption(keyPair.getPrivate());

        try {
            signer.signRtagChallenge(new EnumMap<>(BucketType.class));
            fail("missing rtag was signed");
        } catch (XrootdException e) {
            assertEquals(kGSErrBadRndmTag, e.getError());
        }
    }

    @Test
    public void shouldSignBareDigestWhenBothSidesSupportIt() throws Exception {
        Handler signer = new Handler(PROTO_RTAG_HASH, PROTO_RTAG_HASH);
        signer.rsaSession.initializeForEncryption(keyPair.getPrivate());

        String rtag = GSIRequestHandler.generateChallengeString();
        byte[] signed = signer.signRtagChallenge(rtagBuckets(rtag));

        /*
         * The signed payload is the bare 32 byte digest. Every DigestInfo is
         * at least 34 bytes, so no PKCS#1 v1.5 verifier accepts it.
         */
        Cipher cipher = Cipher.getInstance(GSIRequestHandler.ASYNC_CIPHER_MODE, "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        assertArrayEquals(GSIRequestHandler.rtagDigest(ascii(rtag)), cipher.doFinal(signed));
    }

    @Test
    public void shouldAgreeForAllVersionPairs() throws Exception {
        for (int local : VERSIONS) {
            for (int remote : VERSIONS) {
                Handler signer = new Handler(local, remote);
                Handler verifier = new Handler(remote, local);
                assertEquals(local >= PROTO_RTAG_HASH && remote >= PROTO_RTAG_HASH,
                      signer.useRtagHash());
                signAndVerify(signer, verifier);
            }
        }
    }

    @Test
    public void shouldFailIfRemoteVersionUnknown() throws Exception {
        Handler signer = new Handler(PROTO_RTAG_HASH, PROTO_RTAG_HASH);
        Handler verifier = new Handler(PROTO_RTAG_HASH, 0);

        try {
            signAndVerify(signer, verifier);
            fail("digest accepted as plain tag");
        } catch (XrootdException e) {
            assertEquals(kGSErrBadRndmTag, e.getError());
        }
    }

    @Test
    public void shouldRejectWrongChallenge() throws Exception {
        Handler signer = new Handler(PROTO_RTAG_HASH, PROTO_RTAG_HASH);
        Handler verifier = new Handler(PROTO_RTAG_HASH, PROTO_RTAG_HASH);
        signer.rsaSession.initializeForEncryption(keyPair.getPrivate());
        verifier.rsaSession.initializeForDecryption(keyPair.getPublic());

        verifier.challenge = "abcdefgh";
        byte[] signed = signer.signRtagChallenge(rtagBuckets("abcdefgi"));

        try {
            verifier.verifySignedRTag(signedRtagBuckets(signed));
            fail("wrong challenge accepted");
        } catch (XrootdException e) {
            assertEquals(kGSErrBadRndmTag, e.getError());
        }
    }

    private static void signAndVerify(Handler signer, Handler verifier)
          throws Exception {
        signer.rsaSession.initializeForEncryption(keyPair.getPrivate());
        verifier.rsaSession.initializeForDecryption(keyPair.getPublic());

        verifier.challenge = GSIRequestHandler.generateChallengeString();
        byte[] signed = signer.signRtagChallenge(rtagBuckets(verifier.challenge));
        verifier.verifySignedRTag(signedRtagBuckets(signed));
    }

    private static Map<BucketType, GSIBucket> rtagBuckets(String rtag) {
        Map<BucketType, GSIBucket> buckets = new EnumMap<>(BucketType.class);
        buckets.put(kXRS_rtag, new StringBucket(kXRS_rtag, rtag));
        return buckets;
    }

    private static Map<BucketType, GSIBucket> signedRtagBuckets(byte[] signed) {
        Map<BucketType, GSIBucket> buckets = new EnumMap<>(BucketType.class);
        buckets.put(kXRS_signed_rtag, new RawBucket(kXRS_signed_rtag, signed));
        return buckets;
    }

    private static byte[] sha256DigestInfo() {
        byte[] digestInfo = new byte[SHA256_DIGEST_INFO_PREFIX.length + 32];
        System.arraycopy(SHA256_DIGEST_INFO_PREFIX, 0, digestInfo, 0,
              SHA256_DIGEST_INFO_PREFIX.length);
        return digestInfo;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(US_ASCII);
    }
}
