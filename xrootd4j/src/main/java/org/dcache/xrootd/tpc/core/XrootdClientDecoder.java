/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.core;

import static org.dcache.xrootd.protocol.XrootdProtocol.SERVER_RESPONSE_LEN;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_attn;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_close;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_handshake;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_read;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_redirect;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_wait;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_waitresp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.util.List;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundChecksumResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundCloseResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundEndSessionResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundHandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundOpenReadOnlyResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundProtocolResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundRedirectResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitRespResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitResponse;
import org.dcache.xrootd.tpc.protocol.messages.XrootdInboundResponse;
import org.dcache.xrootd.util.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FrameDecoder for translating xrootd frames into
 * {@link XrootdInboundResponse} objects.</p>.
 *
 * Intended to support third-party client requests to a source server.</p>
 */
public class XrootdClientDecoder extends ByteToMessageDecoder {

    private static final Logger LOGGER =
          LoggerFactory.getLogger(XrootdClientDecoder.class);

    protected final XrootdTpcClient client;
    protected final String sourceUrn;

    public XrootdClientDecoder(XrootdTpcClient client) {
        this.client = client;
        sourceUrn = client.getInfo().getSrc();
    }

    @Override
    protected void decode(ChannelHandlerContext ctx,
          ByteBuf in,
          List<Object> out) {
        ChannelId id = ctx.channel().id();
        int readable = in.readableBytes();

        if (readable < SERVER_RESPONSE_LEN) {
            return;
        }

        int pos = in.readerIndex();
        int headerFrameLength = in.getInt(pos + 4);

        if (headerFrameLength < 0) {
            LOGGER.error("Decoder {}, channel {}: received illegal "
                        + "frame length in "
                        + "xrootd header: {}."
                        + " Closing channel.",
                  sourceUrn, id, headerFrameLength);
            ctx.channel().close();
            return;
        }

        int length = SERVER_RESPONSE_LEN + headerFrameLength;

        if (readable < length) {
            return;
        }

        ByteBuf frame = in.readSlice(length);
        int requestId = client.getExpectedResponse();

        try {
            switch (frame.getUnsignedShort(2)) {
                case kXR_error:
                    LOGGER.debug("Decoder {}, channel {}: adding error response.",
                          sourceUrn, id);
                    out.add(new InboundErrorResponse(frame));
                    return;
                case kXR_wait:
                    LOGGER.debug("Decoder {}, channel {}: adding wait response.",
                          sourceUrn, id);
                    out.add(new InboundWaitResponse(frame, requestId));
                    return;
                case kXR_waitresp:
                    LOGGER.debug("Decoder {}, channel {}: adding waitresp response.",
                          sourceUrn, id);
                    out.add(new InboundWaitRespResponse(frame, requestId));
                    return;
                case kXR_redirect:
                    LOGGER.debug("Decoder {}, channel {}: adding redirect response.",
                          sourceUrn, id);
                    out.add(new InboundRedirectResponse(frame, requestId));
                    return;
                case kXR_attn:
                    LOGGER.debug("Decoder {}, channel {}: adding attn response.",
                          sourceUrn, id);
                    out.add(new InboundAttnResponse(frame, requestId));
                    return;
            }

            switch (requestId) {
                case kXR_handshake:
                    LOGGER.debug("Decoder {}, channel {}: adding handshake response.",
                          sourceUrn, id);
                    out.add(new InboundHandshakeResponse(frame));
                    break;
                case kXR_protocol:
                    LOGGER.debug("Decoder {}, channel {}: adding protocol response.",
                          sourceUrn, id);
                    out.add(new InboundProtocolResponse(frame));
                    break;
                case kXR_login:
                    LOGGER.debug("Decoder {}, channel {}: adding login response.",
                          sourceUrn, id);
                    out.add(new InboundLoginResponse(frame));
                    break;
                case kXR_auth:
                    LOGGER.debug("Decoder {}, channel {}: adding authentication response.",
                          sourceUrn, id);
                    out.add(new InboundAuthenticationResponse(frame));
                    break;
                case kXR_open:
                    LOGGER.debug("Decoder {}, channel {}: adding open response.",
                          sourceUrn, id);
                    out.add(new InboundOpenReadOnlyResponse(frame));
                    break;
                case kXR_read:
                    LOGGER.debug("Decoder {}, channel {}: adding read response.",
                          sourceUrn, id);
                    out.add(new InboundReadResponse(frame));
                    break;
                case kXR_query:
                    LOGGER.debug("Decoder {}, channel {}: adding query response.",
                          sourceUrn, id);
                    out.add(new InboundChecksumResponse(frame));
                    break;
                case kXR_close:
                    LOGGER.debug("Decoder {}, channel {}: adding close response.",
                          sourceUrn, id);
                    out.add(new InboundCloseResponse(frame));
                    break;
                case kXR_endsess:
                    LOGGER.debug("Decoder {}, channel {}: adding endsess response.",
                          sourceUrn, id);
                    out.add(new InboundEndSessionResponse(frame));
                    break;
                default:
                    LOGGER.debug("Decoder {}, channel {}, received incorrect "
                                + "response of request type {}.",
                          sourceUrn, id, requestId);
                    throw new XrootdException(kXR_error,
                          "received incorrect response type.");
            }
        } catch (ParseException | XrootdException e) {
            LOGGER.error("Decoder {}, channel {}: error for request type {}: {}. "
                        + "Closing channel.",
                  requestId, id, e.getMessage());
            client.setError(e);
            client.shutDown(ctx);
        }
    }
}
