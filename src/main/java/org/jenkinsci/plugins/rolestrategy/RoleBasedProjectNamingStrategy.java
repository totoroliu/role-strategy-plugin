package org.jenkinsci.plugins.rolestrategy;

import com.michelin.cio.hudson.plugins.rolestrategy.Messages;
import com.michelin.cio.hudson.plugins.rolestrategy.Role;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;
import hudson.Extension;
import hudson.model.Failure;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import jenkins.model.Jenkins;
import jenkins.model.ProjectNamingStrategy;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Set;
import java.util.SortedMap;
import java.util.regex.Pattern;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Kanstantsin Shautsou
 * @since 2.2.0
 */
public class RoleBasedProjectNamingStrategy extends ProjectNamingStrategy implements Serializable {

    private static final long serialVersionUID = 1L;

    private final boolean forceExistingJobs;

    private static final Logger LOGGER = Logger.getLogger(RoleBasedProjectNamingStrategy.class.getName());

    @DataBoundConstructor
    public RoleBasedProjectNamingStrategy(boolean forceExistingJobs) {
        this.forceExistingJobs = forceExistingJobs;
    }

    @Override
    public void checkName(String name) throws Failure {
        LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): start", new Object[] {name} );
        boolean matches = false;
        ArrayList<String> badList = null;
        AuthorizationStrategy auth = Jenkins.getInstance().getAuthorizationStrategy();
        if (auth instanceof RoleBasedAuthorizationStrategy){
            RoleBasedAuthorizationStrategy rbas = (RoleBasedAuthorizationStrategy) auth;
            //firstly check global role
            SortedMap<Role, Set<String>> gRole = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL);
            for (SortedMap.Entry<Role, Set<String>> entry: gRole.entrySet()){
                LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): Global Role: {1}", new Object[] {name, entry.getKey()} );
                if (entry.getKey().hasPermission(Item.CREATE))
                    LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): Global Role: {1}: return", new Object[] {name, entry.getKey()} );
                    return;
            }
            // check project role with pattern
            SortedMap<Role, Set<String>> roles = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.PROJECT);
            badList = new ArrayList<String>(roles.size());
            for (SortedMap.Entry<Role, Set<String>> entry: roles.entrySet())  {
                Role key = entry.getKey();
                LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): Project Role: {1}", new Object[] {name, key} );
                if (key.hasPermission(Item.CREATE)) {
                    String namePattern = key.getPattern().toString();
                    if (StringUtils.isNotBlank(namePattern) && StringUtils.isNotBlank(name)) {
                        LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): Pattern.matches({1}, {0})", new Object[] {name, namePattern} );
                        if (Pattern.matches(namePattern, name)){
                            matches = true;
                            LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): matches=true", new Object[] {name} );
                        } else {
                            badList.add(namePattern);
                            LOGGER.log(Level.INFO, "OUT: RoleBasedProjectNamingStrategy.checkName({0}}): badList.add({1})", new Object[] {name, namePattern} );
                        }
                    }
                }
            }
        }
        if (!matches) {
            String error;
            if (badList != null && !badList.isEmpty())
                //TODO beatify long outputs?
                error = jenkins.model.Messages.Hudson_JobNameConventionNotApplyed(name, badList.toString());
            else
                error = Messages.RoleBasedProjectNamingStrategy_NoPermissions();
            throw new Failure(error);
        }
    }

    @Override
    public boolean isForceExistingJobs() {
        return forceExistingJobs;
    }

    @Extension
    public static final class DescriptorImpl extends ProjectNamingStrategyDescriptor {

        @Override
        public String getDisplayName() {
            String name = Messages.RoleBasedAuthorizationStrategy_DisplayName();
            if (!RoleBasedAuthorizationStrategy.isCreateAllowed())
                name += " (<font color=\"red\">(Require >1.565 core)</font>";
            return name;
        }

    }
}
