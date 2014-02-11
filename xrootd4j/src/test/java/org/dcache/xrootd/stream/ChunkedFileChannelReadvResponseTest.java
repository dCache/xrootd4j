/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.stream;

import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.List;

import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage;
import org.dcache.xrootd.protocol.messages.ReadResponse;
import org.dcache.xrootd.protocol.messages.ReadVRequest;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

public class ChunkedFileChannelReadvResponseTest
{
    private static final int SOME_ID = 1234;
    private static final int SOME_FH = 1;
    private static final int HEADER = 16;

    private List<FileChannel> _channels;
    private GenericReadRequestMessage.EmbeddedReadRequest[] _requests;
    private ReadVRequest _request;

    @Before
    public void setUp()
    {
        _channels = Lists.newArrayList();
        _requests = new GenericReadRequestMessage.EmbeddedReadRequest[0];
        _request = mock(ReadVRequest.class);
        when(_request.getStreamId()).thenReturn(SOME_ID);
        when(_request.getReadRequestList()).thenReturn(_requests);
    }

    @Test
    public void shouldReturnSingleResponseIfAllowedByMaxFrameSize()
        throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(10000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(100).forLength(200);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(300).forLength(100);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);
        ReadResponse response1 = response.nextChunk();
        ReadResponse response2 = response.nextChunk();

        assertThat(response1.getDataLength(), is(HEADER + 200 + HEADER + 100));
        assertThat(response2, is(nullValue()));
    }

    @Test(expected=IllegalStateException.class)
    public void shouldFailReadsBiggerThanMaxFrameSize() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(10000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(100).forLength(2000);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);
        response.nextChunk();
    }

    @Test
    public void shouldRespectMaxFrameSize() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(10000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(100).forLength(100);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(300).forLength(1000);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);
        ReadResponse response1 = response.nextChunk();
        ReadResponse response2 = response.nextChunk();
        ReadResponse response3 = response.nextChunk();

        assertThat(response1.getDataLength(), is(HEADER + 100));
        assertThat(response2.getDataLength(), is(HEADER + 1000));
        assertThat(response3, is(nullValue()));
    }

    @Test
    public void shouldRespectEndOfFile() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(10000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(9700).forLength(500);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);
        ReadResponse response1 = response.nextChunk();
        ReadResponse response2 = response.nextChunk();

        assertThat(response1.getDataLength(), is(HEADER + 300));
        assertThat(response2, is(nullValue()));
    }

    @Test
    public void shouldUsePositionIndependentRead() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(10000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(100).forLength(100);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(200).forLength(100);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(400).forLength(1000);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(9700).forLength(1000);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);
        ReadResponse response1 = response.nextChunk();
        ReadResponse response2 = response.nextChunk();
        ReadResponse response3 = response.nextChunk();

        verify(channel(SOME_FH)).read(any(ByteBuffer.class), eq(100L));
        verify(channel(SOME_FH)).read(any(ByteBuffer.class), eq(200L));
        verify(channel(SOME_FH)).read(any(ByteBuffer.class), eq(400L));
        verify(channel(SOME_FH)).read(any(ByteBuffer.class), eq(9700L));
    }

    @Test
    public void shouldPackTruncatedReadsInSingleFrameIfPossible() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(400);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(100).forLength(200);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(300).forLength(1000);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);

        ReadResponse response1 = response.nextChunk();
        ReadResponse response2 = response.nextChunk();

        assertThat(response1.getDataLength(), is(HEADER + 200 + HEADER + 100));
        assertThat(response2, is(nullValue()));
    }

    @Test(expected = IllegalStateException.class)
    public void shouldNotOverflowWithLargeRequests() throws Exception
    {
        givenFileDescriptor().withFileHandle(SOME_FH).withSize(Integer.MAX_VALUE);
        givenReadRequest().forFileHandle(SOME_FH).atOffset(0).forLength(Integer.MAX_VALUE);

        AbstractChunkedReadvResponse response = aResponseWithMaxFrameSizeOf(1024);

        ReadResponse response1 = response.nextChunk();
    }

    private FileDescriptorMaker givenFileDescriptor()
    {
        return new FileDescriptorMaker();
    }

    private ReadRequestMaker givenReadRequest()
    {
        int idx = _requests.length;
        _requests = Arrays.copyOf(_requests, _requests.length + 1);
        _requests[idx] = mock(GenericReadRequestMessage.EmbeddedReadRequest.class);
        _request = mock(ReadVRequest.class);
        when(_request.getStreamId()).thenReturn(SOME_ID);
        when(_request.getReadRequestList()).thenReturn(_requests);
        return new ReadRequestMaker(_requests[idx]);
    }

    private FileChannel channel(int fd)
    {
        return _channels.get(fd);
    }

    private AbstractChunkedReadvResponse aResponseWithMaxFrameSizeOf(int maxFrameSize)
    {
        return new
            ChunkedFileChannelReadvResponse(_request, maxFrameSize, _channels);
    }

    /** A builder of FileDescriptor with a fluent interface. */
    private class FileDescriptorMaker
    {
        private final FileChannel channel = mock(FileChannel.class);

        public FileDescriptorMaker() {
        }

        public FileDescriptorMaker withFileHandle(int fh) {
            while (fh >= _channels.size()) {
                _channels.add(null);
            }
            _channels.set(fh, channel);
            return this;
        }

        public FileDescriptorMaker withSize(final long length) throws IOException {
            when(channel.size()).thenReturn(length);
            when(channel.read(any(ByteBuffer.class), anyInt())).thenAnswer(new Answer() {
                @Override
                public Object answer(InvocationOnMock invocation) {
                    Object[] args = invocation.getArguments();
                    ByteBuffer buffer = (ByteBuffer) args[0];
                    long position = (Long) args[1];

                    if (position >= length) {
                        return -1;
                    }

                    int actualRead = (int) Math.min(buffer.remaining(), length - position);
                    buffer.position(buffer.position() + actualRead);
                    return actualRead;
                }
            });
            return this;
        }
    }

    /** A builder of EmbeddedReadRequest with a fluent interface. */
    private static class ReadRequestMaker
    {
        private final GenericReadRequestMessage.EmbeddedReadRequest _request;

        private ReadRequestMaker(GenericReadRequestMessage.EmbeddedReadRequest request) {
            _request = request;
        }

        public ReadRequestMaker forFileHandle(int fh) {
            when(_request.getFileHandle()).thenReturn(fh);
            return this;
        }

        public ReadRequestMaker forLength(int bytes) {
            when(_request.BytesToRead()).thenReturn(bytes);
            return this;
        }

        public ReadRequestMaker atOffset(long position) {
            when(_request.getOffset()).thenReturn(position);
            return this;
        }
    }
}
