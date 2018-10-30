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
package org.dcache.xrootd.core;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import org.dcache.xrootd.protocol.messages.AbstractXrootdRequest;
import org.dcache.xrootd.protocol.messages.SigverRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.security.BufferDecrypter;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgInvalid;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_nodata;
import static org.dcache.xrootd.protocol.messages.SigverRequest.SIGVER_VERSION;

/**
 * <p>Provides signed hash verification capabilities.</p>
 *
 * <p>Maintains the last seqno used on this TCP connection, as
 *    well as the last sigver request.  When the next request
 *    arrives, verifies that its hash matches the signature of
 *    the sigver request.  If the protocol requires generalized
 *    encryption (session key), the signature is first decrypted
 *    using the provided module.</p>
 */
public class XrootdSigverRequestHandler
{
    private final BufferDecrypter decryptionHandler;

    private SigverRequest currentSigverRequest;
    private long lastSeqNo = -1L;

    public XrootdSigverRequestHandler()
    {
        decryptionHandler = null;
    }

    public XrootdSigverRequestHandler(BufferDecrypter decryptionHandler)
    {
        this.decryptionHandler = decryptionHandler;
    }

    public void setSigver(SigverRequest request) throws XrootdException
    {
        if (request.getSeqno() <= lastSeqNo) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " bad sequence number.");
        }

        if (request.getVersion() != SIGVER_VERSION) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " unsupported version number.");
        }

        if (!request.isSHA256()) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " unsupported crypto hash.");
        }

        if (request.isRSAKey()) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " unsupported use of RSA key.");
        }

        currentSigverRequest = request;
    }

    public AbstractXrootdRequest verifySignedHash(ByteBuf frame,
                                                  AbstractXrootdRequest request,
                                                  boolean forceSigning,
                                                  ChannelHandlerContext ctx)
                    throws XrootdException
    {
        if (currentSigverRequest == null) {
            if (decryptionHandler != null || forceSigning) {
                throw new XrootdException(kXR_error,
                                          "signed hash verification: "
                                                          + "did not receive preceding "
                                                          + "sigver request for "
                                                          + request.getStreamId()
                                                          + ", "
                                                          + request.getRequestId());
            }
            return request;
        }

        if (currentSigverRequest.getStreamId() != request.getStreamId()) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " stream id mismatch.");
        }

        if (currentSigverRequest.getExpectrid() != request.getRequestId()) {
            throw new XrootdException(kXR_ArgInvalid,
                                      "signed hash verification:"
                                                      + " request id mismatch.");
        }

        byte[] received = null;

        if (decryptionHandler != null) {
            try {
                currentSigverRequest.decrypt(decryptionHandler);
                received = currentSigverRequest.getSignature();
            } catch (NoSuchPaddingException
                            | InvalidAlgorithmParameterException
                            | NoSuchAlgorithmException
                            | IllegalBlockSizeException
                            | BadPaddingException
                            | NoSuchProviderException
                            | InvalidKeyException e) {
                throw new XrootdException(kXR_error, e.toString());
            }
        } else if (forceSigning) {
            received = currentSigverRequest.getSignature();
        }

        if (received != null) {
            byte[] contents = extractContents(frame,
                                              request,
                                              currentSigverRequest.getFlags(),
                                              ctx);
            compareHashes(received,
                          generateHash(currentSigverRequest.getSeqno(),
                                       contents,
                                       ctx));
        }

        updateSeqNo();

        return request;
    }

    private void compareHashes(byte[] received, byte[] generated)
                    throws XrootdException
    {
        if (received.length != generated.length) {
            throw new XrootdException(kXR_error, "signed hash verification:"
                            + " received hash length does not match generated hash.");
        }

        if (!Arrays.equals(received, generated)) {
            throw new XrootdException(kXR_error, "signed hash verification:"
                            + " received hash does not match generated hash.");
        }
    }

    private byte[] extractContents(ByteBuf frame,
                                   AbstractXrootdRequest request,
                                   int flags,
                                   ChannelHandlerContext ctx)
        throws XrootdException
    {
        /*
         *  If this is a write request, kXR_nodata should be set;
         *  extract only the header.
         */
        if (request instanceof WriteRequest) {
            if (flags != kXR_nodata) {
                throw new XrootdException(kXR_error,
                                          "signed hash verification:"
                                                          + " kXR_nodata not set, "
                                                          + "cannot verify write "
                                                          + "request.");
            }
           return ((WriteRequest)request).getHeaderOnly(ctx);
        }

        byte[] contents = new byte[frame.readableBytes()];
        frame.getBytes(0, contents);

        return contents;
    }

    /**
     *  A signature consists of a SHA-256 hash of
     *    1. an unsigned 64-bit sequence number,
     *    2. the request header, and
     *    3. the request payload,
     *  in that exact order.
     *
     *  In this case, 2 + 3 are given in order by the frame buffer, which
     *  contains the raw bytes of the request.
     */
    private byte[] generateHash(long seqno,
                                byte[] payload,
                                ChannelHandlerContext ctx)
                    throws XrootdException
    {
        ByteBuf buffer = ctx.alloc().buffer(8 + payload.length);
        try {
            buffer.writeLong(seqno);
            buffer.writeBytes(payload);
            byte[] contents = new byte[buffer.readableBytes()];
            buffer.getBytes(0, contents);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(contents);
        } catch (NoSuchAlgorithmException e) {
            throw new XrootdException(kXR_error, e.toString());
        } finally {
            buffer.release();
        }
    }

    private void updateSeqNo()
    {
        lastSeqNo = currentSigverRequest.getSeqno();
        currentSigverRequest = null;
    }
}
