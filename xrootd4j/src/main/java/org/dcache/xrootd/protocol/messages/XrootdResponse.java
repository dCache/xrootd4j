package org.dcache.xrootd.protocol.messages;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

/**
 * A xrootd response message.
 *
 * Response objects may be reference counted.
 */
public interface XrootdResponse
{
    /**
     * Returns the request this is a response to.
     */
    XrootdRequest getRequest();


    /**
     * The xrootd response status code.
     */
    int getStatus();

    /**
     * Writes the encoded message to the given channel context.
     *
     * Does not flush the channel. This is a destructive call and must at
     * most be called once. Decreases the reference count by {@code 1} and
     * deallocates this object if the reference count reaches {@code 0}.
     */
    void writeTo(ChannelHandlerContext ctx, ChannelPromise promise);
}
