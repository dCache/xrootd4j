#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.util.Map;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import javax.security.auth.Subject;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import org.dcache.xrootd.plugins.AuthorizationHandler;

public class PluginAuthorizationHandler implements AuthorizationHandler
{
    @Override
    public String authorize(Subject subject,
                            InetSocketAddress localAddress,
                            InetSocketAddress remoteAddress,
                            String path,
                            Map<String, String> opaque,
                            int request,
                            FilePerm mode)
            throws SecurityException, GeneralSecurityException
    {
        return path;
    }
}
