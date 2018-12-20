/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ssl.HostnameToCertificateChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.SecureRandom;
import java.util.List;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.XrootdBucket;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;

/**
 * <p>Shared fields and functionality for GSI authentication handlers.
 *    Not abstract so it can be both composed and extended.</p>
 */
class BaseGSIAuthenticationHandler
{
    public static final String PROTOCOL = "gsi";
    public static final int PROTOCOL_VERSION = 10200;
    public static final String CRYPTO_MODE = "ssl";

    /**
     * for now, we limit ourselves to AES-128 with CBC blockmode.
     */
    public static final String SUPPORTED_CIPHER_ALGORITHMS = "aes-128-cbc";

    public static final String SUPPORTED_DIGESTS = "sha1:md5";

    /**
     * RSA algorithm, no block chaining mode (not a block-cipher) and PKCS1
     * padding, which is recommended to be used in conjunction with RSA
     */
    protected static final String SERVER_ASYNC_CIPHER_MODE = "RSA/NONE/PKCS1Padding";

    /** the sync cipher mode supported by the server. Unless this is made
     * configurable (todo), it has to match the SUPPORTED_CIPHER_ALGORITHMS
     * advertised by the server
     */
    protected static final String SERVER_SYNC_CIPHER_MODE = "AES/CBC/PKCS5Padding";

    protected static final String SERVER_SYNC_CIPHER_NAME = "AES";

    /**
     * blocksize in bytes
     */
    protected static final int SERVER_SYNC_CIPHER_BLOCKSIZE = 16;
    protected static final int CHALLENGE_BYTES = 8;

    protected static final Logger LOGGER =
        LoggerFactory.getLogger(BaseGSIAuthenticationHandler.class);

    /**
     * cryptographic helper classes
     */
    protected static final SecureRandom RANDOM = new SecureRandom();

    protected static final  HostnameToCertificateChecker CERT_CHECKER =
        new HostnameToCertificateChecker();

    static class XrootdBucketContainer
    {
        private final int                _size;
        private final List<XrootdBucket> _buckets;

        public XrootdBucketContainer(List<XrootdBucket> buckets, int size)
        {
            _buckets = buckets;
            _size = size;
        }

        public int getSize()
        {
            return _size;
        }

        public List<XrootdBucket> getBuckets()
        {
            return _buckets;
        }
    }

    /**
     * certificates/keys/trust-anchors
     */
    protected final X509Credential         credential;
    protected final X509CertChainValidator validator;
    protected final File                   certDir;

    protected BaseGSIAuthenticationHandler(X509Credential credential,
                                           X509CertChainValidator validator,
                                           String certDir)
    {
        this.credential = credential;
        this.validator = validator;
        this.certDir = new File(certDir);
    }

    /**
     * Generate a new challenge string to be used in server-client
     * communication
     * @return challenge string
     */
    protected String generateChallengeString()
    {
        byte[] challengeBytes = new byte[CHALLENGE_BYTES];

        /*
         * RANDOM.nextBytes(...) can not be used, since this generates
         * signed bytes. Upon encoding as string, Java will map negative bytes
         * to 63 (ASCII 'A'). As this would affect the randomness of the
         * challenge string, use the following loop instead.
         */
        for (int i = 0; i < CHALLENGE_BYTES; i++) {
            challengeBytes[i] = (byte) RANDOM.nextInt(Byte.MAX_VALUE);
        }

        return new String(challengeBytes, US_ASCII);
    }

    protected void checkCaIdentities(String[] caIdentities)
                    throws XrootdException
    {
        for (String ca : caIdentities)
        {
            if (!isValidCaPath(ca)) {
                throw new XrootdException(kXR_error, ca
                                + " is not a valid ca cert path.");
            }
        }
    }

    protected void checkVersion(String version)
    {
        // NOP for now
    }

    private boolean isValidCaPath(String path)
    {
        path = path.trim();

        if (path.indexOf(".") < 1) {
            path += ".0";
        }

        return new File(certDir, path).exists();
    }
}
