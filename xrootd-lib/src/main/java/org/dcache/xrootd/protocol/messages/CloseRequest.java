package org.dcache.xrootd.protocol.messages;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class CloseRequest extends AbstractRequestMessage
{
    private final int fileHandle;

    public CloseRequest(ChannelBuffer buffer)
    {
        super(buffer);

        if (getRequestID() != XrootdProtocol.kXR_close)
            throw new IllegalArgumentException("doesn't seem to be a kXR_close message");

        fileHandle = buffer.getInt(4);
    }

    public int getFileHandle()
    {
        return fileHandle;
    }
}
