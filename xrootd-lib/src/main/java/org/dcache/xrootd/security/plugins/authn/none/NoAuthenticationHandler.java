package org.dcache.xrootd.security.plugins.authn.none;

import javax.security.auth.Subject;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OKResponse;
import org.dcache.xrootd.security.AuthenticationHandler;

/**
 * Dummy authentication handler that accepts all authentication requests in
 * authenticate
 *
 * @author tzangerl
 *
 */
public class NoAuthenticationHandler implements AuthenticationHandler {

    @Override
    public AbstractResponseMessage authenticate(AuthenticationRequest request) {
        return new OKResponse(request.getStreamID());
    }

    @Override
    public String getProtocol() {
        return "";
    }

    /**
     * start with empty subject for noauthentication handler
     */
    @Override
    public Subject getSubject() {
        return new Subject();
    }

    @Override
    public boolean isAuthenticationCompleted() {
        return true;
    }

    @Override
    public boolean isStrongAuthentication() {
        return false;
    }

}
