package org.dcache.xrootd.protocol.messages;

import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdSession;

/**
 * An xrootd request message.
 *
 * Request objects may be reference counted.
 */
public interface XrootdRequest
{
    /**
     * Returns the stream id. The stream id is used by the client to
     * match responses to requests.
     */
    int getStreamId();

    /**
     * Returns the request id. The request id identifies the type of
     * the request.
     */
    int getRequestId();

    /**
     * Associates the request with an xrootd session.
     */
    void setSession(XrootdSession session);

    /**
     * Returns the xrootd session associated with the request. A session
     * is established during authentication. May be null.
     */
    XrootdSession getSession();

    /**
     * Returns the subject as identified by the associated session. May be null.
     */
    Subject getSubject();
}
