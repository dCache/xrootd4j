/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.BufferEncrypter;

/**
 * Uses established shared secret from a Diffie Hellman session to
 *    encrypt or decrypt the buffer.</p>
 */
public class DHBufferHandler implements BufferEncrypter, BufferDecrypter {

    private DHSession session;
    private String cipherSpec;
    private String keySpec;
    private int blocksize;

    public DHBufferHandler(DHSession session,
          String cipherSpec,
          String keySpec,
          int blocksize) {
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
          NoSuchProviderException {
        /*
         *  REVISIT
         *
         *  see https://github.com/xrootd/xrootd/issues/1046
         *
         *  It would seem that xrootd v4.10.0+ has decided to extend
         *  the signature length by the length of the IV buffer (16 bytes)
         *  used to encrypt it.
         *
         *  While justification for this is still unclear, we need to
         *  ensure that the hash verification continues to work.
         *
         *  The SHA256 hash of the message contents is always 32 bytes long,
         *  so any excess bytes appended to the first 32 can simply be discarded.
         *
         *  In any case, it would seem that those extra 16 bytes
         *  consistently decode to:
         *
         *      0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10
         *      0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10
         *
         *  We may end up reverting this when the above GitHub issue is
         *  resolved.
         */
        byte[] full = session.decrypt(cipherSpec, keySpec, blocksize, encrypted);
        if (full.length > 32) {
            return Arrays.copyOf(full, 32);
        }
        return full;
    }

    @Override
    public byte[] encrypt(byte[] unencrypted)
          throws InvalidKeyException, IllegalStateException,
          NoSuchAlgorithmException, NoSuchPaddingException,
          IllegalBlockSizeException, BadPaddingException,
          InvalidAlgorithmParameterException,
          NoSuchProviderException {
        /*
         *  REVISIT
         *
         *  see https://github.com/xrootd/xrootd/issues/1046
         *
         *  It would seem that xrootd v4.10.0+ has decided to extend
         *  the signature length by the length of the IV buffer (16 bytes)
         *  used to encrypt it.
         *
         *  While justification for this is still unclear, we need to
         *  ensure that the hash verification continues to work.
         *
         *  We need to append the 16 bytes it is expecting.  As noted above,
         *  those consistently decode to:
         *
         *      0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10
         *      0x10 0x10 0x10 0x10 0x10 0x10 0x10 0x10
         *
         *  We may end up reverting this when the above GitHub issue is
         *  resolved.
         */
        int origLen = unencrypted.length;
        unencrypted = Arrays.copyOf(unencrypted, origLen + 16);
        for (int i = 0; i < 16; i++) {
            unencrypted[origLen + i] = (byte) 16;
        }
        return session.encrypt(cipherSpec, keySpec, blocksize, unencrypted);
    }
}
