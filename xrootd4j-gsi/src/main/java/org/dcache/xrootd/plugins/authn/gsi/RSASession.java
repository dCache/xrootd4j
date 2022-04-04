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
package org.dcache.xrootd.plugins.authn.gsi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.ASYNC_CIPHER_MODE;

/**
 *  This class is necessitated by the fact that the new GSI protocol requires
 *  encryption and decryption of the arbitrarily long Diffie-Hellman
 *  encoded parameters.
 *
 *  RSA encryption/decryption is not recommended for block-like processing
 *  of messages, but this is the way that the SLAC client and server do it,
 *  so we are constrained to follow suit.
 */
public class RSASession
{
    protected static Logger LOGGER = LoggerFactory.getLogger(RSASession.class);

    protected Cipher        cipher;
    protected int           maxDecryptionBlockSize;
    protected int           maxEncryptionBlockSize;

    /**
     * Prepare rsaCipher for encryption using local private key.
     */
    public void initializeForEncryption(PrivateKey privateKey)
                    throws NoSuchPaddingException, NoSuchAlgorithmException,
                    NoSuchProviderException, InvalidKeyException
    {
        cipher = Cipher.getInstance(ASYNC_CIPHER_MODE, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

        /*
         *  Magic number (= 2*sha1_outlen + 2)
         *  This is from the SLAC xrootd 4.9 XrdCryptosslRSA c++ class.
         */
        maxEncryptionBlockSize = (rsaPrivateKey.getModulus().bitLength()/8) - 11;
        LOGGER.debug("RSA cipher initialized for encryption using private key "
                                     + "of length {}, max block size {}.",
                     rsaPrivateKey.getEncoded().length,
                     maxEncryptionBlockSize);
    }

    /**
     * Prepare rsaCipher for decryption using received public key.
     */
    public void initializeForDecryption(PublicKey publicKey)
                    throws NoSuchPaddingException, NoSuchAlgorithmException,
                    NoSuchProviderException, InvalidKeyException
    {
        cipher = Cipher.getInstance(ASYNC_CIPHER_MODE, "BC");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        /*
         *  This is from the SLAC xrootd 4.9 XrdCryptosslRSA c++ class.
         */
        maxDecryptionBlockSize = (rsaPublicKey.getModulus().bitLength()/8);
        LOGGER.debug("RSA cipher initialized for decryption using public key "
                                     + "of length {}, max block size {}.",
                     rsaPublicKey.getEncoded().length,
                     maxEncryptionBlockSize);
    }

    public byte[] encrypt(byte[] in) throws IOException, BadPaddingException,
                    IllegalBlockSizeException
    {
        LOGGER.debug("RSA cipher encryption, incoming length {}; max block {}.",
                     in.length, maxEncryptionBlockSize);
        return translate(in, maxEncryptionBlockSize);
    }

    public byte[] decrypt(byte[] in) throws IOException, BadPaddingException,
                    IllegalBlockSizeException
    {
        LOGGER.debug("RSA cipher decryption, in length {}; max block {}.",
                     in.length, maxDecryptionBlockSize);
        return translate(in, maxDecryptionBlockSize);
    }

    private byte[] translate(byte[] in, int maxBlockLen)
                    throws BadPaddingException, IllegalBlockSizeException,
                    IOException
    {
        ByteArrayInputStream inStream = new ByteArrayInputStream(in);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();

        int len = in.length;
        byte[] block = new byte[maxBlockLen];
        while (len > 0) {
            int blockLen = Math.min(len, maxBlockLen);
            LOGGER.debug("RSA cipher processing block of length {}.", blockLen);
            inStream.read(block, 0, blockLen);
            outStream.write(cipher.doFinal(block, 0, blockLen));
            len -= blockLen;
        }

        return outStream.toByteArray();
    }
}
