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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.dcache.xrootd.security.BufferDecrypter;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_sigver;

/**
 * <p>Request to verify signature.</p>
 *
 * * <p>According to protocol, has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_sigver</td></tr>
 *      <tr><td>kXR_unt16</td><td>expectrid</td></tr>
 *      <tr><td>kXR_char</td><td>version</td></tr>
 *      <tr><td>kXR_char</td><td>flags</td></tr>
 *      <tr><td>kXR_unt64</td><td>seqno</td></tr>
 *      <tr><td>kXR_char</td><td>crypto</td></tr>
 *      <tr><td>kXR_char</td><td>reserved[3]</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *  </table>
 */
public class SigverRequest extends AbstractXrootdRequest
{
    public static final  int    kXR_SHA256 =   0x01;
    public static final  int    kXR_rsaKey =   0x80;
    public static final  int    kXR_HashMask = 0x0F;
    public static final  int    SIGVER_VERSION = 0;

    private final long seqno;
    private final int  expectrid;
    private final byte flags;
    private final byte crypto;
    private final byte version;

    /*
     * Overridden when decrypted.
     */
    private byte[] signature;

    public SigverRequest(ByteBuf buffer)
    {
        super(buffer, kXR_sigver);

        expectrid = buffer.getShort(4);
        version = buffer.getByte(6);
        flags = buffer.getByte(7); // should == kXR_nodata if this is a write
        seqno = buffer.getLong(8);
        crypto = buffer.getByte(16);

        /*
         * skip reserved [bytes 17-19]
         */

        int dlen = buffer.getInt(20);
        signature = new byte[dlen];
        buffer.getBytes(24, signature);
    }

    public void decrypt(BufferDecrypter decrypter)
                    throws NoSuchPaddingException,
                    InvalidAlgorithmParameterException,
                    NoSuchAlgorithmException, IllegalBlockSizeException,
                    BadPaddingException, NoSuchProviderException,
                    InvalidKeyException
    {
        signature = decrypter.decrypt(signature);
    }

    public byte getCrypto()
    {
        return crypto;
    }

    public byte getVersion()
    {
        return version;
    }

    public boolean isSHA256()
    {
        return ((int)crypto & kXR_HashMask) == kXR_SHA256;
    }

    public boolean isRSAKey()
    {
        return ((int)crypto & kXR_rsaKey) == kXR_rsaKey;
    }

    public byte[] getSignature()
    {
        return signature;
    }

    public int getExpectrid()
    {
        return expectrid;
    }

    public byte getFlags()
    {
        return flags;
    }

    public long getSeqno()
    {
        return seqno;
    }
}
