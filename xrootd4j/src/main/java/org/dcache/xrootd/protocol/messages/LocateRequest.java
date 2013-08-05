package org.dcache.xrootd.protocol.messages;

import org.jboss.netty.buffer.ChannelBuffer;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_locate;

public class LocateRequest extends PathRequest
{
    private int options;

    public LocateRequest(ChannelBuffer buffer)
    {
        super(buffer, kXR_locate);
        options = buffer.getUnsignedMedium(4);
    }

    public int getOptions()
    {
        return options;
    }

    public boolean hasFlag(int flag)
    {
        return (options & flag) == flag;
    }

    @Override
    public String toString()
    {
        return "locate[" + getPath() + ";" + options + "]";
    }
}
