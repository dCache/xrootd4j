package org.dcache.xrootd.protocol.messages;

import java.util.Arrays;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class ReadVRequest extends GenericReadRequestMessage
{
    public ReadVRequest(ChannelBuffer buffer)
    {
        super(buffer);

        if (getRequestID() != XrootdProtocol.kXR_readv) {
            throw new IllegalArgumentException("doesn't seem to be a kXR_readv message");
        }
    }

    public int NumberOfReads()
    {
        return getSizeOfList();
    }

    @Override
    public EmbeddedReadRequest[] getReadRequestList()
    {
        return super.getReadRequestList();
    }

    @Override
    public String toString()
    {
        return String.format("readv[%d,%s]",
                             getPathID(),
                             Arrays.toString(getReadRequestList()));
    }
}
