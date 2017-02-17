/*
 * The MIT License
 *
 * Copyright (c) 2010, Manufacture Française des Pneumatiques Michelin, Thomas Maurel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.michelin.cio.hudson.plugins.rolestrategy;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.MapMaker;
import com.synopsys.arc.jenkins.plugins.rolestrategy.Macro;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleMacroExtension;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.User;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import hudson.security.SidACL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import jenkins.model.Jenkins;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.acls.sid.Sid;
import org.acegisecurity.userdetails.UserDetails;
import org.jenkinsci.plugins.rolestrategy.Settings;
import org.springframework.dao.DataAccessException;


/**
 * Class holding a map for each kind of {@link AccessControlled} Object, associating
 * each {@link Role} with the concerned {@link User}s/groups.
 * @author Thomas Maurel
 */
public class RoleMap {

  /** Map associating each {@link Role} with the concerned {@link User}s/groups. */
  private final SortedMap <Role,Set<String>> grantedRoles;

  protected static final Logger LOGGER = Logger.getLogger(RoleMap.class.getName());
  
  private final Cache<String, UserDetails> cache = CacheBuilder.newBuilder()
          .softValues()
          .maximumSize(Settings.USER_DETAILS_CACHE_MAX_SIZE)
          .expireAfterWrite(Settings.USER_DETAILS_CACHE_EXPIRATION_TIME_SEC, TimeUnit.SECONDS)
          .build();

  RoleMap() {
    this.grantedRoles = new TreeMap<Role, Set<String>>();
  }

  RoleMap(SortedMap<Role,Set<String>> grantedRoles) {
    this.grantedRoles = grantedRoles;
  }

  /**
   * Check if the given sid has the provided {@link Permission}.
   * @return True if the sid's granted permission
   */
  private boolean hasPermission(String sid, Permission p, RoleType roleType, AccessControlled controlledItem) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): start", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
    LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): role = getRolesHavingPermission(p))", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
    for(Role role : getRolesHavingPermission(p)) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): role={4}", new Object[] {sid.hashCode(), p, roleType, controlledItem, role.getName().hashCode()} );
        if(this.grantedRoles.get(role).contains(sid)) {
            LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): this.grantedRoles.get(role={4}).contains(sid={0})", new Object[] {sid.hashCode(), p, roleType, controlledItem, role.getName().hashCode()} );
            // Handle roles macro
            if (Macro.isMacro(role)) {
                LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): Macro.isMacro(role)==true", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
                Macro macro = RoleMacroExtension.getMacro(role.getName());
                if (macro != null) {
                    RoleMacroExtension macroExtension = RoleMacroExtension.getMacroExtension(macro.getName());
                    if (macroExtension.IsApplicable(roleType) && macroExtension.hasPermission(sid, p, roleType, controlledItem, macro)) {
                        LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): return true", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
                        return true;
                    }
                }
            } // Default handling
            else {
                LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): Macro.isMacro(role)==false", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
                LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): return true", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
                return true;
            }
        } else if (Settings.TREAT_USER_AUTHORITIES_AS_ROLES) {
            LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): Settings.TREAT_USER_AUTHORITIES_AS_ROLES", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
            try {
                UserDetails userDetails = cache.getIfPresent(sid);
                if (userDetails == null) {
                    userDetails = Jenkins.getInstance().getSecurityRealm().loadUserByUsername(sid);
                    cache.put(sid, userDetails);
                }
                for (GrantedAuthority grantedAuthority : userDetails.getAuthorities()) {
                    LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): grantedAuthority.getAuthority().equals({4})", new Object[] {sid.hashCode(), p, roleType, controlledItem, role.getName().hashCode()} );
                    if (grantedAuthority.getAuthority().equals(role.getName())) {
                        LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): return true", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
                        return true;
                    }
                }
            } catch (BadCredentialsException e) {
                LOGGER.log(Level.FINE, "Bad credentials", e);
            } catch (DataAccessException e) {
                LOGGER.log(Level.FINE, "failed to access the data", e);
            } catch (RuntimeException ex) {
                // There maybe issues in the logic, which lead to IllegalStateException in Acegi Security (JENKINS-35652)
                // So we want to ensure this method does not fail horribly in such case
                LOGGER.log(Level.WARNING, "Unhandled exception during user authorities processing", ex);
            }
        }

        // TODO: Handle users macro
    }
    LOGGER.log(Level.INFO, "OUT: RoleMap.hasPermission(sid={0}, p={1}, roleType={2}, controlledItem={3}): return false", new Object[] {sid.hashCode(), p, roleType, controlledItem} );
    return false;
  }

  /**
   * Check if the {@link RoleMap} contains the given {@link Role}.
   * @return True if the {@link RoleMap} contains the given role
   */
  public boolean hasRole(Role role) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.hasRole(role={0}): start", role.getName().hashCode());
    LOGGER.log(Level.INFO, "OUT: RoleMap.hasRole(role={0}): return this.grantedRoles.containsKey(role)", role.getName().hashCode());
    return this.grantedRoles.containsKey(role);
  }

  /**
   * Get the ACL for the current {@link RoleMap}.
   * @return ACL for the current {@link RoleMap}
   */
  public SidACL getACL(RoleType roleType, AccessControlled controlledItem) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getACL(roleType={0}, controlledItem={1}): start", new Object[]{roleType, controlledItem});
    LOGGER.log(Level.INFO, "OUT: RoleMap.getACL(roleType={0}, controlledItem={1}): return new AclImpl(roleType, controlledItem)", new Object[]{roleType, controlledItem});
    return new AclImpl(roleType, controlledItem);
  }

  /**
   * Add the given role to this {@link RoleMap}.
   * @param role The {@link Role} to add
   */
  public void addRole(Role role) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.addRole(role={0})", role.getName().hashCode());
    if(this.getRole(role.getName()) == null) {
      this.grantedRoles.put(role, new HashSet<String>());
    }
  }

  /**
   * Assign the sid to the given {@link Role}.
   * @param role The {@link Role} to assign the sid to
   * @param sid The sid to assign
   */
  public void assignRole(Role role, String sid) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.assignRole(role={0}, sid={1})", new Object[] {role.getName().hashCode(), sid.hashCode()});
    if(this.hasRole(role)) {
      this.grantedRoles.get(role).add(sid);
    }
  }

  /**
   * Clear all the sids associated to the given {@link Role}.
   * @param role The {@link Role} for which you want to clear the sids
   */
  public void clearSidsForRole(Role role) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.clearSidsForRole(role={0})", role.getName().hashCode());
    if(this.hasRole(role)) {
      this.grantedRoles.get(role).clear();
    }
  }

  /**
   * Clear all the sids for each {@link Role} of the {@link RoleMap}.
   */
  public void clearSids() {
    LOGGER.log(Level.INFO, "OUT: RoleMap.clearSids(): start");
    for(Map.Entry<Role, Set<String>> entry : this.grantedRoles.entrySet()) {
      Role role = entry.getKey();
      LOGGER.log(Level.INFO, "OUT: RoleMap.clearSids(): this.clearSidsForRole(role={0})", role.getName().hashCode());
      this.clearSidsForRole(role);
    }
  }

  /**
   * Get the {@link Role} Object named after the given param.
   * @param name The name of the {@link Role}
   * @return The {@link Role} named after the given param
   */
  public Role getRole(String name) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getRole(name={0}): start", name.hashCode());
    for(Role role : this.getRoles()) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.getRole(name={0}): role={1}", new Object[] {name.hashCode(), role.getName().hashCode()});
      if(role.getName().equals(name)) {
        LOGGER.log(Level.INFO, "OUT: RoleMap.getRole(name={0}): return role={1}", new Object[] {name.hashCode(), role.getName().hashCode()});
        return role;
      }
    }
    LOGGER.log(Level.INFO, "OUT: RoleMap.getRole(name={0}): return null", name.hashCode());
    return null;
  }

  /**
   * Get an unmodifiable sorted map containing {@link Role}s and their assigned sids.
   * @return An unmodifiable sorted map containing the {@link Role}s and their associated sids
   */
  public SortedMap<Role, Set<String>> getGrantedRoles() {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getGrantedRoles()");
    return Collections.unmodifiableSortedMap(this.grantedRoles);
  }

  /**
   * Get an unmodifiable set containing all the {@link Role}s of this {@link RoleMap}.
   * @return An unmodifiable set containing the {@link Role}s
   */
  public Set<Role> getRoles() {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getRoles()");
    return Collections.unmodifiableSet(this.grantedRoles.keySet());
  }

  /**
   * Get all the sids referenced in this {@link RoleMap}, minus the {@code Anonymous} sid.
   * @return A sorted set containing all the sids, minus the {@code Anonymous} sid
   */
  public SortedSet<String> getSids() {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSids()");
    return this.getSids(false);
  }

  /**
   * Get all the sids referenced in this {@link RoleMap}.
   * @param includeAnonymous True if you want the {@code Anonymous} sid to be included in the set
   * @return A sorted set containing all the sids
   */
  public SortedSet<String> getSids(Boolean includeAnonymous) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSids(includeAnonymous={0}): start", includeAnonymous);
    TreeSet<String> sids = new TreeSet<String>();
    for(Map.Entry entry : this.grantedRoles.entrySet()) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.getSids(includeAnonymous={0}): sids.addAll({1})", new Object[]{includeAnonymous, (Set)entry.getValue()} );
      sids.addAll((Set)entry.getValue());
    }
    // Remove the anonymous sid if asked to
    if(!includeAnonymous) {
      sids.remove("anonymous");
    }
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSids(includeAnonymous={0}): return Collections.unmodifiableSortedSet(sids={1})", new Object[]{includeAnonymous, sids} );
    return Collections.unmodifiableSortedSet(sids);
  }

  /**
   * Get all the sids assigned to the {@link Role} named after the {@code roleName} param.
   * @param roleName The name of the role
   * @return A sorted set containing all the sids
   */
  public Set<String> getSidsForRole(String roleName) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSidsForRole(roleName={0}): start", roleName);
    Role role = this.getRole(roleName);
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSidsForRole(roleName={0}): role={1}", new Object[]{roleName, role.getName().hashCode()});
    if(role != null) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.getSidsForRole(roleName={0}): return Collections.unmodifiableSet(this.grantedRoles.get(role={1}))", new Object[]{roleName, role.getName().hashCode()});
      return Collections.unmodifiableSet(this.grantedRoles.get(role));
    }
    LOGGER.log(Level.INFO, "OUT: RoleMap.getSidsForRole(roleName={0}): return null", roleName);
    return null;
  }

  /**
   * Create a sub-map of the current {@link RoleMap} containing only the
   * {@link Role}s matching the given pattern.
   * @param namePattern The pattern to match
   * @return A {@link RoleMap} containing only {@link Role}s matching the given name
   */
  public RoleMap newMatchingRoleMap(String namePattern) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.newMatchingRoleMap(namePattern={0}): start", namePattern);
    Set<Role> roles = getMatchingRoles(namePattern);
    SortedMap<Role, Set<String>> roleMap = new TreeMap<Role, Set<String>>();
    for(Role role : roles) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.newMatchingRoleMap(namePattern={0}): roleMap.put(role={1}, this.grantedRoles.get(role))", new Object[]{namePattern, role.getName().hashCode()});
      roleMap.put(role, this.grantedRoles.get(role));
    }
    LOGGER.log(Level.INFO, "OUT: RoleMap.newMatchingRoleMap(namePattern={0}): return new RoleMap(roleMap=)", new Object[]{namePattern, roleMap});
    return new RoleMap(roleMap);
  }

  /**
   * Get all the roles holding the given permission.
   * @param permission The permission you want to check
   * @return A Set of Roles holding the given permission
   */
  private Set<Role> getRolesHavingPermission(final Permission permission) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getRolesHavingPermission(permission={0}): start", permission);
    final Set<Role> roles = new HashSet<Role>();
    final Set<Permission> permissions = new HashSet<Permission>();
    Permission p = permission;

    // Get the implying permissions
    for(; p!=null; p=p.impliedBy) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.getRolesHavingPermission(permission={0}): permissions.add(p={1})", new Object[]{permission, p} );
      permissions.add(p);
    }
    // Walk through the roles, and only add the roles having the given permission,
    // or a permission implying the given permission
    new RoleWalker() {
      public void perform(Role current) {
        if(current.hasAnyPermission(permissions)) {
          roles.add(current);
        }
      }
    };

    LOGGER.log(Level.INFO, "OUT: RoleMap.getRolesHavingPermission(permission={0}): return roles=", new Object[]{permission, roles} );
    return roles;
  }

  /**
   * Get all the roles whose pattern match the given pattern.
   * @param namePattern The string to match
   * @return A Set of Roles matching the given name
   */
  private Set<Role> getMatchingRoles(final String namePattern) {
    LOGGER.log(Level.INFO, "OUT: RoleMap.getMatchingRoles(namePattern={0}): start", namePattern);
    final Set<Role> roles = new HashSet<Role>();

    // Walk through the roles and only add the Roles whose pattern matches the given string
    new RoleWalker() {
      public void perform(Role current) {
        Matcher m = current.getPattern().matcher(namePattern);
        if(m.matches()) {
          roles.add(current);
        }
      }
    };

    LOGGER.log(Level.INFO, "OUT: RoleMap.getMatchingRoles(namePattern={0}): return roles=", new Object[]{namePattern, roles} );
    return roles;
  }

  /**
   * The Acl class that will delegate the permission check to the {@link RoleMap} Object.
   */
  private final class AclImpl extends SidACL {

    AccessControlled item;
    RoleType roleType;

    public AclImpl(RoleType roleType, AccessControlled item) {
        LOGGER.log(Level.INFO, "OUT: RoleMap.AclImpl.AclImpl(roleType={0}, item={1}): constructor", new Object[]{roleType, item} );
        this.item = item;
        this.roleType = roleType;
    }
      
    /**
     * Checks if the sid has the given permission.
     * <p>Actually only delegate the check to the {@link RoleMap} instance.</p>
     * @param p The sid to check
     * @param permission The permission to check
     * @return True if the sid has the given permission
     */
    @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL", justification = "As declared in Jenkins API")
    @Override
    protected Boolean hasPermission(Sid p, Permission permission) {
      LOGGER.log(Level.INFO, "OUT: RoleMap.AclImpl.hasPermission(sid p={0}, permission={1}): start", new Object[]{p, permission});
      if(RoleMap.this.hasPermission(toString(p), permission, roleType, item)) {
        LOGGER.log(Level.INFO, "OUT: RoleMap.AclImpl.hasPermission(sid p={0}, permission={1}): return true", new Object[]{p, permission});
        return true;
      }
      LOGGER.log(Level.INFO, "OUT: RoleMap.AclImpl.hasPermission(sid p={0}, permission={1}): return null", new Object[]{p, permission});
      return null;
    }
  }

  /**
   * A class to walk through all the {@link RoleMap}'s roles and perform an
   * action on each one.
   */
  private abstract class RoleWalker {

    RoleWalker() {
      walk();
    }

    /**
     * Walk through the roles.
     */
    public void walk() {
      LOGGER.log(Level.INFO, "OUT: RoleMap.RoleWalker.walk(): start");
      Set<Role> roles = RoleMap.this.getRoles();
      Iterator iter = roles.iterator();
      while (iter.hasNext()) {
        Role current = (Role) iter.next();
        LOGGER.log(Level.INFO, "OUT: RoleMap.RoleWalker.walk(): perform(current={0})", current);
        perform(current);
      }
    }

    /**
     * The method to implement which will be called on each {@link Role}.
     */
    abstract public void perform(Role current);
  }

}
