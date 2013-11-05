package org.dcache.xrootd.protocol.messages;

import com.google.common.base.Joiner;

import java.net.InetSocketAddress;

import org.dcache.xrootd.protocol.XrootdProtocol;

public class LocateResponse extends AbstractResponseMessage
{
    private String encoded;

    public LocateResponse(XrootdRequest request, InfoElement... info)
    {
        this(request, encode(info));
    }

    private LocateResponse(XrootdRequest request, String encoded)
    {
        super(request, XrootdProtocol.kXR_ok, encoded.length());
        this.encoded = encoded;
        putCharSequence(encoded);
    }

    public static String encode(InfoElement[] info)
    {
        return Joiner.on(" ").join(info);
    }

    public enum Node
    {
        MANAGER("M"), MANAGER_PENDING("m"), SERVER("S"), SERVER_PENDING("s");

        String value;

        Node(String value)
        {
            this.value = value;
        }
    }

    public enum Access
    {
        READ("r"), WRITE("w");

        String value;

        Access(String value)
        {
            this.value = value;
        }
    }

    public static class InfoElement
    {
        private final InetSocketAddress address;
        private final Node node;
        private final Access access;

        public InfoElement(InetSocketAddress address, Node node, Access access)
        {

            this.address = address;
            this.node = node;
            this.access = access;
        }

        @Override
        public String toString()
        {
            return node.value + access.value + "[::" + address.getAddress().getHostAddress() + "]:" + address.getPort();
        }
    }

    @Override
    public String toString()
    {
        return "locate-reponse[" + encoded + "]";
    }
}
