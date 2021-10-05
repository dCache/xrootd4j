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
package org.dcache.xrootd.plugins.authn.gsi;

import static io.netty.buffer.Unpooled.wrappedBuffer;
import static org.dcache.xrootd.core.XrootdDecoder.readAscii;
import static org.dcache.xrootd.core.XrootdEncoder.writeZeroPad;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.messages.LoginResponse.AUTHN_PROTOCOL_TYPE_LEN;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_main;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_version;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getClientStep;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getServerStep;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_certreq;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_reserved;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_pxyreq;

import io.netty.buffer.ByteBuf;
import java.io.IOException;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *  Utilities for deserializing, writing, and printing out GSI byte buckets.
 */
public class GSIBucketUtils {

    private static final Logger LOGGER
          = LoggerFactory.getLogger(GSIBucketUtils.class);

    private static final String BYTE_DUMP[] =
          {
                "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x    %s\n",
                "//  0x%02x                                                     %s\n",
                "//  0x%02x 0x%02x                                              %s\n",
                "//  0x%02x 0x%02x 0x%02x                                       %s\n",
                "//  0x%02x 0x%02x 0x%02x 0x%02x                                %s\n",
                "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x                         %s\n",
                "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x                  %s\n",
                "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x           %s\n"
          };

    public static class BucketSerializerBuilder {

        private final BucketSerializer serializer;

        public BucketSerializerBuilder() {
            serializer = new BucketSerializer();
        }

        public BucketSerializerBuilder withTitle(String title) {
            serializer.title = title;
            return this;
        }

        public BucketSerializerBuilder withStreamId(Integer streamId) {
            serializer.streamId = streamId;
            return this;
        }

        public BucketSerializerBuilder withRequestId(Integer requestId) {
            serializer.requestId = requestId;
            return this;
        }

        public BucketSerializerBuilder withStat(Integer stat) {
            serializer.stat = stat;
            return this;
        }

        public BucketSerializerBuilder withStepName(String stepName) {
            serializer.stepName = stepName;
            return this;
        }

        public BucketSerializerBuilder withProtocol(String protocol) {
            serializer.protocol = protocol;
            return this;
        }

        public BucketSerializerBuilder withStep(int step) {
            serializer.step = step;
            return this;
        }

        public BucketSerializerBuilder withBuckets(List<GSIBucket> buckets) {
            serializer.buckets = buckets;
            return this;
        }

        public BucketSerializer build() {
            return serializer;
        }
    }

    public static class BucketSerializer implements Consumer<ByteBuf> {

        String title;
        Integer streamId;
        Integer requestId;
        Integer stat;
        String stepName;
        String protocol;
        int step;
        List<GSIBucket> buckets;

        @Override
        public void accept(ByteBuf byteBuf) {
            writeBytes(byteBuf, protocol, step, buckets);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace(describe(title,
                      b -> dumpBuckets(b, buckets, stepName),
                      streamId,
                      requestId,
                      stat));
            }
        }
    }

    /**
     *  The Xrootd GSI protocol passes handshake information in structs
     *  that are called "buckets".  Each bucket has embedded in it
     *  the four fields (protocol, step, version) as well as a length
     *  integer for the length of the actual data.
     *
     *  All of this gets serialized into the byte data fields of the
     *  Authentication requests and responses (which other protocols
     *  may structure differently.)
     */
    public static class BucketData {

        /**
         * The protocol, zero-padded char[4]
         */
        String protocol;

        /**
         * The step, int32
         */
        int step;

        /**
         *  The protocol version.
         */
        Integer version;

        /**
         * The buckets (kind of a serialized datatype with an
         * int32 block of metadata).
         */
        final Map<BucketType, GSIBucket> bucketMap = new EnumMap<>(BucketType.class);

        public String getProtocol() {
            return protocol;
        }

        public int getStep() {
            return step;
        }

        public Integer getVersion() {
            return version;
        }

        public Map<BucketType, GSIBucket> getBucketMap() {
            return bucketMap;
        }
    }

    /**
     * Deserialize an XrootdBucket. Depending on the BucketType, return an
     * XrootdBucket of a specific subtype.
     *
     * The only type where the returned type is not a-priori known is
     * kXRS_main, which can be encrypted. If it is encrypted, a binary (raw)
     * bucket is returned, if it is not encyrpted, a list of contained
     * buckets (nestedBuffer) is returned.
     *
     * @param type The type of the bucket that should be deserialized
     * @param buffer The buffer containing the buckets
     * @return The deserialized bucket
     */
    public static GSIBucket deserialize(BucketType type, ByteBuf buffer)
          throws IOException {

        GSIBucket bucket;

        switch (type) {

            case kXRS_main:

                try {

                    bucket = deserializeNested(type, buffer);

                } catch (IOException e) {
                    // ok the nested buffer seems to be encrypted
                    // just store the binary data for now, it will be decrypted later on
                    bucket = RawBucket.deserialize(type, buffer);
                }

                break;

            case kXRS_cryptomod:    // fall through
            case kXRS_issuer_hash:  // fall through
            case kXRS_rtag:         // fall through
            case kXRS_puk:          // fall through
            case kXRS_cipher_alg:   // fall through
            case kXRS_x509:         // fall through
            case kXRS_x509_req:     // fall through
            case kXRS_md_alg:       // fall through
            case kXRS_message:      // fall through

                bucket = StringBucket.deserialize(type, buffer);
                break;

            case kXRS_version:      // fall through
            case kXRS_clnt_opts:

                bucket = UnsignedIntBucket.deserialize(type, buffer);
                break;

            default:

                bucket = RawBucket.deserialize(type, buffer);
                break;
        }

        return bucket;
    }

    /**
     * Deserialize the buckets sent by the client and put them into a EnumMap
     * sorted by their header-information. As there are list-type buffers,
     * this method can be called recursively. In current xrootd, this is
     * limited to a maximum of 1 recursion (main buffer containing list of
     * further buffers).
     *
     * @param buffer The buffer containing the received buckets
     * @return Map from bucket-type to deserialized buckets
     * @throws IOException Failure of deserialization
     */
    public static Map<BucketType, GSIBucket> deserializeBuckets(ByteBuf buffer)
          throws IOException {

        int bucketCode = buffer.readInt();
        BucketType bucketType = BucketType.get(bucketCode);

        Map<BucketType, GSIBucket> buckets =
              new EnumMap<>(BucketType.class);

        while (bucketType != BucketType.kXRS_none) {
            LOGGER.debug("Deserialized a bucket with code {}, type {}",
                  bucketCode, bucketType);

            int bucketLength = buffer.readInt();

            LOGGER.debug("bucket type {} has length {}.",
                  bucketType, bucketLength);

            GSIBucket bucket = deserialize(bucketType,
                  buffer.slice(buffer.readerIndex(),
                        bucketLength));
            buckets.put(bucketType, bucket);

            /* proceed to the next bucket */
            buffer.readerIndex(buffer.readerIndex() + bucketLength);

            bucketCode = buffer.readInt();
            bucketType = BucketType.get(bucketCode);
        }

        return buckets;
    }

    public static BucketData deserializeData(AuthenticationRequest request) {
        BucketData data = new BucketData();
        ByteBuf buffer = request.getCredentialBuffer();

        data.protocol = deserializeProtocol(buffer);
        data.step = deserializeStep(buffer);

        try {
            data.bucketMap.putAll(GSIBucketUtils.deserializeBuckets(buffer));
        } catch (IOException ioex) {
            throw new IllegalArgumentException("Illegal credential format: {}",
                  ioex);
        }

        request.releaseBuffer();

        UnsignedIntBucket versionBucket
              = (UnsignedIntBucket) data.bucketMap.get(kXRS_version);

        if (versionBucket != null) {
            data.version = versionBucket.getContent();
        }

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe("//                Authentication Request",
                  b -> dumpBuckets(b,
                        data.bucketMap.values(),
                        getClientStep(data.step)),
                  request.getStreamId(),
                  request.getRequestId(),
                  null));
        }

        return data;
    }

    public static BucketData deserializeData(InboundAuthenticationResponse response)
          throws XrootdException {
        BucketData data = new BucketData();
        ByteBuf buffer = response.getDataBuffer();
        data.protocol = deserializeProtocol(buffer);
        data.step = deserializeStep(buffer);

        try {
            data.bucketMap.putAll(GSIBucketUtils.deserializeBuckets(buffer));

            /*
             *  if pxyreq, do not deserialize and unpack the main bucket.
             */
            if (data.step != kXGS_pxyreq) {
                RawBucket mainBucket = (RawBucket) data.bucketMap.remove(kXRS_main);
                ByteBuf mainBuffer = wrappedBuffer(mainBucket.getContent());
                /*
                 *   protocol and server step are repeated inside this bucket;
                 *   skip.
                 */
                mainBuffer.readerIndex(8);
                data.bucketMap.putAll(GSIBucketUtils.deserializeBuckets(mainBuffer));
            }
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.toString());
        }

        response.releaseBuffer();

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe("//           Inbound Authentication Response",
                  b -> dumpBuckets(b,
                        data.bucketMap.values(),
                        getServerStep(data.step)),
                  response.getStreamId(),
                  response.getRequestId(),
                  response.getStatus()));
        }

        return data;
    }

    /**
     * Deserialize the NestedBucketBuffer. Retrieve all the buckets and
     * recursively deserialize them. Also, retrieve the protocol information
     * and the step.
     *
     * @param type The type of the bucket (usually kXRS_main)
     * @param buffer The buffer containing the nested bucket buffer
     * @return Deserialized buffer
     * @throws IOException Deserialization fails
     */
    public static NestedBucketBuffer deserializeNested(BucketType type, ByteBuf buffer)
          throws IOException {
        /* kXRS_main can be a nested or an encrypted (raw) bucket. Try whether it
         * looks like a nested buffer and use raw deserialization if not */
        int readIndex = buffer.readerIndex();

        String protocol = deserializeProtocol(buffer);

        int step = deserializeStep(buffer);

        LOGGER.debug("NestedBucketBuffer protocol: {}, step {}", protocol,
              step);

        if (step < kXGC_certreq || step > kXGC_reserved) {
            /* reset buffer */
            buffer.readerIndex(readIndex);
            throw new IOException("Buffer contents are not a nested buffer!");
        }

        return new NestedBucketBuffer(type, protocol, step,
              deserializeBuckets(buffer));
    }

    public static void dumpBuckets(StringBuilder builder,
          Collection<GSIBucket> buckets,
          String step) {
        int i = 0;

        for (GSIBucket bucket : buckets) {
            i = bucket.dump(builder, step, ++i);
        }
    }

    public static void dumpBytes(StringBuilder builder, byte[] data) {
        int i = 0;
        int D = data.length / 8;

        for (int d = 0; d < D; ++d) {
            builder.append(String.format(BYTE_DUMP[0],
                  data[i], data[i + 1], data[i + 2],
                  data[i + 3], data[i + 4], data[i + 5],
                  data[i + 6], data[i + 7],
                  getAscii(data, i, 8)));
            i += 8;
        }

        switch (data.length % 8) {
            case 7:
                builder.append(String.format(BYTE_DUMP[7],
                      data[i], data[i + 1], data[i + 2],
                      data[i + 3], data[i + 4], data[i + 5],
                      data[i + 6],
                      getAscii(data, i, 7)));
                break;
            case 6:
                builder.append(String.format(BYTE_DUMP[6],
                      data[i], data[i + 1], data[i + 2],
                      data[i + 3], data[i + 4], data[i + 5],
                      getAscii(data, i, 6)));
                break;
            case 5:
                builder.append(String.format(BYTE_DUMP[5],
                      data[i], data[i + 1], data[i + 2],
                      data[i + 3], data[i + 4],
                      getAscii(data, i, 5)));
                break;
            case 4:
                builder.append(String.format(BYTE_DUMP[4],
                      data[i], data[i + 1], data[i + 2],
                      data[i + 3],
                      getAscii(data, i, 4)));
                break;
            case 3:
                builder.append(String.format(BYTE_DUMP[3],
                      data[i], data[i + 1], data[i + 2],
                      getAscii(data, i, 3)));
                break;
            case 2:
                builder.append(String.format(BYTE_DUMP[2],
                      data[i], data[i + 1],
                      getAscii(data, i, 2)));
                break;
            case 1:
                builder.append(String.format(BYTE_DUMP[1],
                      data[i],
                      getAscii(data, i, 1)));
                break;
        }
    }

    public static int getLengthForRequest(GSIBucketContainer container) {
        /*
         *  The request length for GSI carries
         *  protocol (4 bytes) + step (4 bytes) + container size + terminal
         *  marker (4 bytes).
         */
        return 12 + container.getSize();
    }

    private static void writeBytes(ByteBuf buffer, String protocol,
          int step,
          List<GSIBucket> buckets) {
        writeZeroPad(protocol, buffer, 4);
        buffer.writeInt(step);
        for (GSIBucket bucket : buckets) {
            bucket.serialize(buffer);
        }

        buffer.writeInt(BucketType.kXRS_none.getCode());
    }

    private static String describe(String title,
          Consumer<StringBuilder> data,
          Integer streamId,
          Integer requestId,
          Integer stat) {
        StringBuilder builder = new StringBuilder("\n");
        builder.append("/////////////////////////////////////////////////////////\n");
        builder.append(title);
        builder.append("\n//\n");
        builder.append("//  stream:  ").append(streamId).append("\n");
        if (requestId != null) {
            builder.append("//  request: ").append(requestId).append("\n");
        }
        if (stat != null) {
            builder.append("//  stat:    ").append(stat).append("\n");
        }
        builder.append("//\n");
        data.accept(builder);
        builder.append("/////////////////////////////////////////////////////////\n");
        return builder.toString();
    }

    private static String deserializeProtocol(ByteBuf buffer) {
        return readAscii(buffer, AUTHN_PROTOCOL_TYPE_LEN);
    }

    private static int deserializeStep(ByteBuf buffer) {
        return buffer.readInt();
    }

    private static String getAscii(byte[] bytes, int from, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; ++i) {
            byte b = bytes[from + i];
            if (32 < b && b < 127) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private GSIBucketUtils() {
        // Static singleton
    }
}
