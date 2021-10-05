import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.dcache.xrootd.plugins.AuthorizationFactory;

public class PluginAuthorizationFactory implements AuthorizationFactory {

    final static String NAME = "${name}";

    final static Set<String> ALTERNATIVE_NAMES =
          new HashSet(Arrays.asList(NAME));

    static boolean hasName(String name) {
        return ALTERNATIVE_NAMES.contains(name);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return "${description}";
    }

    @Override
    public PluginAuthorizationHandler createHandler() {
        return new PluginAuthorizationHandler();
    }
}
