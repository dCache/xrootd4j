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
package org.dcache.xrootd.core;

import static org.dcache.xrootd.protocol.XrootdProtocol.CLIENT_REQUEST_LEN;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_close;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_dirlist;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_locate;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mv;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_prepare;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_read;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_readv;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_rm;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_rmdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_set;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_sigver;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_stat;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_statx;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_sync;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_write;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.FattrRequest;
import org.dcache.xrootd.protocol.messages.LocateRequest;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.QueryRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.SetRequest;
import org.dcache.xrootd.protocol.messages.SigverRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.UnknownRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for frame decoders.
 *
 * Modified to handle (serial) segmentation of write requests
 * such that the amount of data written never exceeds a maximum
 * direct I/O buffer size.
 */
public abstract class AbstractXrootdDecoder extends ByteToMessageDecoder {

    protected static final Logger LOGGER =
          LoggerFactory.getLogger(AbstractXrootdDecoder.class);

    private int maxWriteBufferSize = Integer.MAX_VALUE;

    private WriteRequest lastWrite;
    private int remainingDataLength;

    public int getMaxWriteBufferSize() {
        return maxWriteBufferSize;
    }

    public void setMaxWriteBufferSize(int maxFrameSize) {
        this.maxWriteBufferSize = maxFrameSize;
    }

    protected XrootdRequest getRequest(ByteBuf frame) {
        if (lastWrite != null) {
            return getWriteRequest(frame);
        }

        int requestId = frame.getUnsignedShort(2);

        switch (requestId) {
            case kXR_sigver:
                return new SigverRequest(frame);
            case kXR_login:
                return new LoginRequest(frame);
            case kXR_prepare:
                return new PrepareRequest(frame);
            case kXR_open:
                return new OpenRequest(frame);
            case kXR_stat:
                return new StatRequest(frame);
            case kXR_statx:
                return new StatxRequest(frame);
            case kXR_read:
                return new ReadRequest(frame);
            case kXR_readv:
                return new ReadVRequest(frame);
            case kXR_write:
                return getWriteRequest(frame);
            case kXR_sync:
                return new SyncRequest(frame);
            case kXR_close:
                return new CloseRequest(frame);
            case kXR_protocol:
                return new ProtocolRequest(frame);
            case kXR_rm:
                return new RmRequest(frame);
            case kXR_rmdir:
                return new RmDirRequest(frame);
            case kXR_mkdir:
                return new MkDirRequest(frame);
            case kXR_mv:
                return new MvRequest(frame);
            case kXR_dirlist:
                return new DirListRequest(frame);
            case kXR_auth:
                return new AuthenticationRequest(frame);
            case kXR_endsess:
                return new EndSessionRequest(frame);
            case kXR_locate:
                return new LocateRequest(frame);
            case kXR_query:
                return new QueryRequest(frame);
            case kXR_set:
                return new SetRequest(frame);
            case kXR_fattr:
            	return new FattrRequest(frame);
            default:
                return new UnknownRequest(frame);
        }
    }

    protected int verifyMessageLength(ByteBuf in) {
        int readable = in.readableBytes();

        /*
         *  This is a partial write subsequent to the first segment.
         */
        if (remainingDataLength > 0) {
            int desiredChunk = Math.min(maxWriteBufferSize, remainingDataLength);
            LOGGER.trace("verifyMessageLength: remaining {}, desired {}, readable {}",
                  remainingDataLength, desiredChunk, readable);
            if (readable < desiredChunk) {
                return 0;
            } else {
                remainingDataLength -= desiredChunk;
                return desiredChunk;
            }
        }

        /*
         *  All other requests have a common framing format with a
         *  fixed length header.
         */
        if (readable < CLIENT_REQUEST_LEN) {
            return 0;
        }

        /*
         *  Reading from a potentially accumulating buffer.
         */
        int pos = in.readerIndex();

        int requestId = in.getUnsignedShort(pos + 2);
        int frameLength = in.getInt(pos + 20);

        if (frameLength < 0) {
            /*
             * disconnect
             */
            return -1;
        }

        LOGGER.trace("verifyMessageLength: {}, frame length: {}",
              XrootdProtocol.getClientRequest(requestId), frameLength);

        int length = CLIENT_REQUEST_LEN + Math.min(frameLength, maxWriteBufferSize);

        if (readable < length) {
            return 0;
        }

        /*
         *  It is only feasible to segment the data payload of a write request;
         *  should any other request exceed the max buffer size, we disconnect.
         */
        if (frameLength > maxWriteBufferSize) {
            if (requestId != kXR_write) {
                /*
                 * disconnect
                 */
                return -1;
            }
            remainingDataLength = frameLength - maxWriteBufferSize;
            LOGGER.trace("verifyMessageLength: write request data length: {}", frameLength);
        } else {
            remainingDataLength = 0;
        }

        return length;
    }

    private WriteRequest getWriteRequest(ByteBuf frame) {
        int streamId;
        int fhandle;
        long offset;
        int length;
        ByteBuf data;

        if (lastWrite == null) {
            streamId = frame.getUnsignedShort(0);
            fhandle = frame.getInt(4);
            offset = frame.getLong(8);
            /*
             *  The full frame size is in the header of this buffer, so we need to
             *  compare to the max size and take the lesser.
             */
            length = Math.min(frame.getInt(20), maxWriteBufferSize);
            data = frame.retainedSlice(24, length);
        } else {
            streamId = lastWrite.getStreamId();
            fhandle = lastWrite.getFileHandle();
            offset = lastWrite.getWriteOffset() + lastWrite.getDataLength();
            length = frame.readableBytes();
            data = frame.retainedSlice(0, length);
        }

        WriteRequest request = new WriteRequest(streamId, fhandle, offset, length, data,
              remainingDataLength);

        LOGGER.trace("getWriteRequest, fhandle {}, offset {}, data length {}; remaining: {}.",
              fhandle, offset, length, remainingDataLength);

        if (remainingDataLength > 0) {
            lastWrite = request;
        } else {
            lastWrite = null;
        }

        return request;
    }
}
