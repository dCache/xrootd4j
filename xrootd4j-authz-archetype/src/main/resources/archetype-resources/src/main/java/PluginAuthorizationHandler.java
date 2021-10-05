import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Map;
import javax.security.auth.Subject;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;

public class PluginAuthorizationHandler implements AuthorizationHandler {

    @Override
    public String authorize(Subject subject,
          InetSocketAddress localAddress,
          InetSocketAddress remoteAddress,
          String path,
          Map<String, String> opaque,
          int request,
          FilePerm mode)
          throws SecurityException, GeneralSecurityException {
        return path;
    }
}
