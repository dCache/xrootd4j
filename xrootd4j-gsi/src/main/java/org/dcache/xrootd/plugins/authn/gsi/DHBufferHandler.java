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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.BufferEncrypter;

/**
 * <p>Uses established shared secret from a Diffie Hellman session to
 *    encrypt or decrypt the buffer.</p>
 */
public class DHBufferHandler implements BufferEncrypter, BufferDecrypter
{
    private DHSession session;
    private String    cipherSpec;
    private String    keySpec;
    private int       blocksize;

    public DHBufferHandler(DHSession session,
                           String cipherSpec,
                           String keySpec,
                           int blocksize)
    {
        this.session = session;
        this.cipherSpec = cipherSpec;
        this.keySpec = keySpec;
        this.blocksize = blocksize;
    }

    @Override
    public byte[] decrypt(byte[] encrypted)
                    throws InvalidKeyException, IllegalStateException,
                    NoSuchAlgorithmException, NoSuchPaddingException,
                    IllegalBlockSizeException, BadPaddingException,
                    InvalidAlgorithmParameterException,
                    NoSuchProviderException
    {
        return session.decrypt(cipherSpec, keySpec, blocksize, encrypted);
    }

    @Override
    public byte[] encrypt(byte[] unencrypted)
                    throws InvalidKeyException, IllegalStateException,
                    NoSuchAlgorithmException, NoSuchPaddingException,
                    IllegalBlockSizeException, BadPaddingException,
                    InvalidAlgorithmParameterException,
                    NoSuchProviderException
    {
        return session.encrypt(cipherSpec, keySpec, blocksize, unencrypted);
    }
}
