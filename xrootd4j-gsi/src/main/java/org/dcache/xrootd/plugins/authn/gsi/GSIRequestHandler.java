/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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

import javax.crypto.Cipher;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Shared settings and functionality for processing both client and server
 * GSI authentication requests.
 */
public abstract class GSIRequestHandler
{
    public static final String PROTOCOL = "gsi";

    public static final int PROTO_WITH_DELEGATION = 10400;
    public static final int PROTO_PRE_DELEGATION  = 10300;
    public static final int PROTOCOL_VERSION      = PROTO_PRE_DELEGATION;

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
    public static final String SERVER_ASYNC_CIPHER_MODE = "RSA/NONE/PKCS1Padding";

    /** the sync cipher mode supported by the server. Unless this is made
     * configurable (todo), it has to match the SUPPORTED_CIPHER_ALGORITHMS
     * advertised by the server
     */
    public static final String SERVER_SYNC_CIPHER_MODE = "AES/CBC/PKCS5Padding";

    public static final String SERVER_SYNC_CIPHER_NAME = "AES";

    /**
     * blocksize in bytes
     */
    public static final int SERVER_SYNC_CIPHER_BLOCKSIZE = 16;
    public static final int CHALLENGE_BYTES = 8;

    /**
     * maximum request time skew
     */
    public static final long MAX_TIME_SKEW = TimeUnit.SECONDS.toMillis(300);

    /**
     * cryptographic helper classes
     */
    protected static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Generate a new challenge string to be used in server-client
     * communication
     * @return challenge string
     */
    public static String generateChallengeString()
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

    protected final GSICredentialManager credentialManager;

    protected DHSession            dhSession;
    protected DHBufferHandler      bufferHandler;
    protected String               challenge = "";
    protected Cipher               challengeCipher;
    protected long                 lastRequest;

    protected GSIRequestHandler(GSICredentialManager credentialManager)
    {
        this.credentialManager = credentialManager;
    }

    public abstract int getProtocolVersion();

    protected void updateLastRequest()
    {
        lastRequest = System.currentTimeMillis();
    }

    protected boolean isRequestExpired()
    {
        if (lastRequest == 0L) {
            lastRequest = System.currentTimeMillis();
            return false;
        }

        return System.currentTimeMillis() - lastRequest >= MAX_TIME_SKEW;
    }
}
