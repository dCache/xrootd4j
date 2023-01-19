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
package org.dcache.xrootd.tpc.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_sigver;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.dcache.xrootd.security.BufferEncrypter;

/**
 * Request to verify signature.</p>
 *
 * * According to protocol, has the following packet structure:</p>
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
public class OutboundSigverRequest extends AbstractXrootdOutboundRequest {

    public static final byte kXR_SHA256 = 0x01;
    private static final byte[] RESERVED = {0, 0, 0};

    private final long seqno;
    private final int expectrid;
    private byte[] signature;

    public OutboundSigverRequest(long seqno,
          AbstractXrootdOutboundRequest request,
          ChannelHandlerContext ctx)
          throws NoSuchAlgorithmException {
        super(request.getStreamId(), kXR_sigver);
        this.seqno = seqno;
        this.expectrid = request.getRequestId();
        signature = getSignature(request, ctx);
    }

    public void encrypt(BufferEncrypter encrypter)
          throws NoSuchPaddingException,
          InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, IllegalBlockSizeException,
          BadPaddingException, NoSuchProviderException,
          InvalidKeyException {
        signature = encrypter.encrypt(signature);
    }

    @Override
    protected void getParams(ByteBuf buffer) {
        buffer.writeShort(expectrid);
        buffer.writeByte(0);
        buffer.writeByte(0); // we do not send write requests, so no data = 0x0
        buffer.writeLong(seqno);
        buffer.writeByte(kXR_SHA256);
        buffer.writeBytes(RESERVED);
        buffer.writeInt(signature.length);
        buffer.writeBytes(signature);
    }

    @Override
    protected int getParamsLen() {
        return 20;
    }

    /**
     *  A signature consists of a SHA-256 hash of
     *    1. an unsigned 64-bit sequence number,
     *    2. the request header, and
     *    3. the request payload,
     *  in that exact order.
     */
    private byte[] getSignature(AbstractXrootdOutboundRequest request,
          ChannelHandlerContext ctx)
          throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        ByteBuf buffer = ctx.alloc().buffer(12 + request.getParamsLen());
        try {
            buffer.writeLong(seqno);
            request.writeToBuffer(buffer);
            byte[] contents = new byte[buffer.readableBytes()];
            buffer.getBytes(0, contents);
            return digest.digest(contents);
        } finally {
            buffer.release();
        }
    }
}
