/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.ztn;

import static org.dcache.xrootd.plugins.authn.ztn.ZTNCredential.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgTooLong;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.AUTHN_PROTOCOL_PREFIX;

import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
import javax.security.auth.Subject;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.security.BufferDecrypter;
import org.dcache.xrootd.security.RequiresTLS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base handler for xrootd-security message exchange based on the ZTN protocol.
 * <p/>
 * Because the specific type of the credential token is not defined by
 * this library, an implementation of this class must be provided.
 */
public abstract class AbstractZTNAuthenticationHandler
      implements AuthenticationHandler, RequiresTLS {

    protected static final Logger LOGGER
          = LoggerFactory.getLogger(AbstractZTNAuthenticationHandler.class);

    protected Subject subject;
    protected ZTNCredential credential;
    protected Set<String> trustedIssuers;

    private Integer maxTokenSize;
    private List<String> alternateTokenLocations;
    private Long tokenUsageFlags;
    private boolean completed;

    @Override
    public XrootdResponse<AuthenticationRequest> authenticate(AuthenticationRequest request)
          throws XrootdException {
        subject = new Subject();

        credential = ZTNCredentialUtils.deserialize(request.getCredentialBuffer());
        request.releaseBuffer();

        LOGGER.trace("ZTNCredential: {}.", credential);

        if (maxTokenSize != null && credential.getNullTerminatedTokenLength() > maxTokenSize) {
            completed = true;
            throw new XrootdException(kXR_ArgTooLong, "token exceeds max length");
        }

        validateToken();

        completed = true;

        return new OkResponse<>(request);
    }

    /**
     * @return the supported protocol. The protocol string also
     * contains version number and max length of the token accepted.
     */
    @Override
    public String getProtocol() {
        StringBuilder protocol = new StringBuilder(AUTHN_PROTOCOL_PREFIX);
        protocol.append(PROTOCOL);

        if (hasParams()) {
            protocol.append(",");

            if (tokenUsageFlags == null) {
                protocol.append(0L);
            } else {
                protocol.append(tokenUsageFlags);
            }

            protocol.append(":");

            if (maxTokenSize == null) {
                protocol.append(Integer.MAX_VALUE);
            } else {
                protocol.append(maxTokenSize);
            }

            protocol.append(":");

            if (alternateTokenLocations != null) {
                StringJoiner joiner = new StringJoiner(",");
                alternateTokenLocations.stream()
                      .map(s -> CharSequence.class.cast(s))
                      .forEach(joiner::add);
                protocol.append(joiner.toString());
            }
        }

        LOGGER.debug("Protocol: {}.", protocol.toString());

        return protocol.toString();
    }

    @Override
    public String getProtocolName() {
        return PROTOCOL;
    }

    @Override
    public Subject getSubject() {
        return subject;
    }

    @Override
    public boolean isCompleted() {
        return completed;
    }

    @Override
    public BufferDecrypter getDecrypter() {
        return null;
    }

    public void setMaxTokenSize(Integer maxTokenSize) {
        this.maxTokenSize = maxTokenSize;
    }

    public void setAlternateTokenLocations(
          List<String> alternateTokenLocations) {
        this.alternateTokenLocations = alternateTokenLocations;
    }

    public void setTokenUsageFlags(Long tokenUsageFlags) {
        this.tokenUsageFlags = tokenUsageFlags;
    }

    public void setTrustedIssuers(Set<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    private boolean hasParams() {
        return maxTokenSize != null ||
              tokenUsageFlags != null ||
              alternateTokenLocations != null;
    }

    protected abstract void validateToken() throws XrootdException;
}
