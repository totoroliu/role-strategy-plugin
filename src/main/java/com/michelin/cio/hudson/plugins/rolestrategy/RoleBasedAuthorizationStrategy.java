/*
 * The MIT License
 *
 * Copyright (c) 2010-2011, Manufacture Française des Pneumatiques Michelin,
 * Thomas Maurel, Romain Seguy, and contributors
 * 
 * Contributions:
 *   - Slave ownership: Oleg Nenashev <nenashev@synopsys.com>, Synopsys Inc.
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

import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType;
import com.synopsys.arc.jenkins.plugins.rolestrategy.UserMacroExtension;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.model.AbstractItem;
import hudson.model.Computer;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.Project;
import hudson.model.Run;
import hudson.model.View;
import hudson.scm.SCM;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.SidACL;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import javax.servlet.ServletException;

import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Role-based authorization strategy.
 * @author Thomas Maurel
 */
public class RoleBasedAuthorizationStrategy extends AuthorizationStrategy {

  public final static String GLOBAL    = "globalRoles";
  public final static String PROJECT   = "projectRoles";
  public final static String SLAVE     = "slaveRoles";
  public final static String MACRO_ROLE = "roleMacros";
  public final static String MACRO_USER  = "userMacros";
  
  private static final Logger LOGGER = Logger.getLogger(RoleBasedAuthorizationStrategy.class.getName());

  private static String printAllStackTraces() {
      Thread currentThread = java.lang.Thread.currentThread();
      String stackTraces = "Current Thread: " + currentThread.getName() + " (" + currentThread.getId() + ")\n";
      Map liveThreads = currentThread.getAllStackTraces();
      for (java.util.Iterator i = liveThreads.keySet().iterator(); i.hasNext(); ) {
        Thread key = (Thread)i.next();
	stackTraces += "Thread " + key.getName() + "\n";
        //LOGGER.log(Level.WARNING, "Thread {0}", key.getName());
          StackTraceElement[] trace = (StackTraceElement[])liveThreads.get(key);
          for (int j = 0; j < trace.length; j++) {
              stackTraces += "\t at " + trace[j] + "\n";
              //LOGGER.log(Level.WARNING, "\tat {0}", trace[j]);
          }
      }
      return stackTraces;
  }
  private static String printCurrentStackTraces() {
      Thread currentThread = java.lang.Thread.currentThread();
      String stackTraces = "Current Thread: " + currentThread.getName() + " (" + currentThread.getId() + ")\n";
      StackTraceElement[] trace = currentThread.getStackTrace();
      //LOGGER.log(Level.WARNING, "Thread {0}", key.getName());
      for (int j = 0; j < trace.length; j++) {
          stackTraces += "\t at " + trace[j] + "\n";
          //LOGGER.log(Level.WARNING, "\tat {0}", trace[j]);
      }
      return stackTraces;
  }
  
  /** {@link RoleMap}s associated to each {@link AccessControlled} class */
  private final Map <String, RoleMap> grantedRoles = new HashMap < String, RoleMap >();

  /**
   * Get the root ACL.
   * @return The global ACL
   */
  @Override
  public SidACL getRootACL() {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRootACL(): start");
    RoleMap root = getRoleMap(GLOBAL);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRootACL(): return root.getACL(RoleType.Global, null)");
    return root.getACL(RoleType.Global, null);
  }

  
  /**
   * Universal function for getting ACL for different 
   * @param roleMapName Name of the role map section
   * @param itemName Name of the item for patterns
   * @return ACL
   */
   private ACL getACL(String roleMapName, String itemName, RoleType roleType, AccessControlled item)
   {
     LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(roleMapName={0}, itemName={1}, roleType={2}, item={3}): start", new Object[] {roleMapName, itemName, roleType, item} );
     LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(roleMapName={0}, itemName={1}, roleType={2}, item={3}): Thread.getAllStackTraces()=\n{4}\n", new Object[] {roleMapName, itemName, roleType, item, printAllStackTraces()} );
     SidACL acl;
     RoleMap roleMap = grantedRoles.get(roleMapName);
     LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(): roleMap={0}", roleMap);
     if(roleMap == null) {
       LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(): roleMap=null");
       LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(): acl=getRootACL()");
       acl = getRootACL();
     }
     else {
       // Create a sub-RoleMap matching the project name, and create an inheriting from root ACL
       LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(): acl = roleMap.newMatchingRoleMap(itemName).getACL(roleType, item).newInheritingACL(getRootACL())");
       acl = roleMap.newMatchingRoleMap(itemName).getACL(roleType, item).newInheritingACL(getRootACL());
     }
     LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(): return acl={0}", acl);
     return acl;   
   }
  
   /**
   * Get the specific ACL for projects.
   * @param project The access-controlled project
   * @return The project specific ACL
   */
    @Override
    public ACL getACL(Job<?,?> project) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(Job<?,?> project={0})", (AbstractItem) project);
      return getACL((AbstractItem) project);
    }

    @Override
    public ACL getACL(AbstractItem project) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(AbstractItem project={0}): start", project);
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(AbstractItem project={0}): Thread.getAllStackTraces()=\n{1}\n", new Object[] {project, printAllStackTraces()} );
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(AbstractItem project={0}): return getACL(PROJECT, project.getFullName(), RoleType.Project, project)", project);
      return getACL(PROJECT, project.getFullName(), RoleType.Project, project);
    }

    @Override
    public ACL getACL(Computer computer) {
       LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getACL(Computer computer={0}", computer);
       return getACL(SLAVE, computer.getName(), RoleType.Slave, computer);
    }
  
  /**
   * Used by the container realm.
   * @return All the sids referenced by the strategy
   */
  @Override
  public Collection<String> getGroups() {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGroups(): start");
    Set<String> sids = new HashSet<String>();
    for(Map.Entry entry : this.grantedRoles.entrySet()) {
      RoleMap roleMap = (RoleMap) entry.getValue();
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGroups(): roleMap={0}", roleMap);
      sids.addAll(roleMap.getSids(true));
    }
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGroups(): return sids={0}", sids);
    return sids;
  }

  /**
   * Get the roles from the global {@link RoleMap}.
   * <p>The returned sorted map is unmodifiable.</p>
   * @param type The object type controlled by the {@link RoleMap}
   * @return All roles from the global {@link RoleMap}
   */
  public SortedMap<Role, Set<String>> getGrantedRoles(String type) {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGrantedRoles(type={0}): start", type);
    RoleMap roleMap = this.getRoleMap(type);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGrantedRoles(type={0}): roleMap={2}", new Object[] {type, roleMap});
    if(roleMap != null) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGrantedRoles(type={0}): return roleMap.getGrantedRoles()", type);
      return roleMap.getGrantedRoles();
    }
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGrantedRoles(type={0}): roleMap=null", type);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getGrantedRoles(type={0}): return null", type);
    return null;
  }

  /**
   * Get all the SIDs referenced by specified {@link RoleMap} type.
   * @param type The object type controlled by the {@link RoleMap}
   * @return All SIDs from the specified {@link RoleMap}.
   */
  public Set<String> getSIDs(String type) {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getSIDs(type={0}): start", type);
    RoleMap roleMap = this.getRoleMap(type);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getSIDs(type={0}): roleMap={1}", new Object[] {type, roleMap});
    if(roleMap != null) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getSIDs(type={0}): return roleMap.getSids()", type);
      return roleMap.getSids();
    }
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getSIDs(type={0}): roleMap=null", type);
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getSIDs(type={0}): return null", type);
    return null;
  }

  /**
   * Get the {@link RoleMap} associated to the given class.
   * @param type The object type controlled by the {@link RoleMap}
   * @return The associated {@link RoleMap}
   */
  private RoleMap getRoleMap(String type) {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRoleMap(type={0}): start", type);
    RoleMap map;
    if(grantedRoles.containsKey(type)) {
       map = grantedRoles.get(type);
    }
    else {
      // Create it if it doesn't exist
      map = new RoleMap();
      grantedRoles.put(type, map);
    }
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRoleMap(type={0}): return map={1}", new Object[] {type, map});
    return map;
  }

  /**
   * Returns a map associating a string representation with each {@link RoleMap}.
   * <p>This method is intended to be used for XML serialization purposes (take
   * a look at the {@link ConverterImpl}) and, as such, must remain private
   * since it exposes all the security config.</p>
   */
  private Map<String, RoleMap> getRoleMaps() {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRoleMaps(): start");
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.getRoleMaps(): return grantedRoles={0}", grantedRoles);
    return grantedRoles;
  }

  /**
   * Add the given {@link Role} to the {@link RoleMap} associated to the provided class.
   * @param type Role type (use constants in {@link RoleBasedAuthorizationStrategy})
   * @param role The {@link Role} to add
   */
  private void addRole(String type, Role role) {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.addRole(type={0}, role={1}): start", new Object[] {type, role} );
    RoleMap roleMap = this.grantedRoles.get(type);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.addRole(type={0}, role={1}): roleMap={2}", new Object[] {type, role, roleMap} );
    if(roleMap != null) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.addRole(type={0}, role={1}): roleMap.addRole(role)", new Object[] {type, role} );
      roleMap.addRole(role);
    } else {
      // Create the RoleMap if it doesnt exist
      roleMap = new RoleMap();
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.addRole(type={0}, role={1}): roleMap.addRole(role)", new Object[] {type, role} );
      roleMap.addRole(role);
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.addRole(type={0}, role={1}): grantedRoles.put({0}, {2})", new Object[] {type, role, roleMap} );
      grantedRoles.put(type, roleMap);
    }
  }

  /**
   * Assign a role to a sid
   * @param type The type of role
   * @param role The role to assign
   * @param sid The sid to assign to
   */
  private void assignRole(String type, Role role, String sid) {
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.assignRole(type={0}, role={1}, sid={2}): start", new Object[] {type, role, sid} );
    RoleMap roleMap = this.grantedRoles.get(type);
    LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.assignRole(type={0}, role={1}, sid={2}): roleMap={3}", new Object[] {type, role, sid, roleMap} );
    if(roleMap != null && roleMap.hasRole(role)) {
      roleMap.assignRole(role, sid);
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.assignRole(type={0}, role={1}, sid={2}): roleMap.assignRole(role={1}, sid={3})", new Object[] {type, role, sid, roleMap} );
    }
  }

  @Extension
  public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

  /**
   * Converter used to persist and retrieve the strategy from disk.
   *
   * <p>This converter is there to manually handle the marshalling/unmarshalling
   * of this strategy: Doing so is a little bit dirty but allows to easily update
   * the plugin when new access controlled object (for the moment: Job and
   * Project) will be introduced. If it's the case, there's only the need to
   * update the getRoleMaps() method.</p>
   */
  public static class ConverterImpl implements Converter {
      public boolean canConvert(Class type) {
        return type==RoleBasedAuthorizationStrategy.class;
      }

      public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        RoleBasedAuthorizationStrategy strategy = (RoleBasedAuthorizationStrategy)source;
        Map<String, RoleMap> maps = strategy.getRoleMaps();
        for(Map.Entry<String, RoleMap> map : maps.entrySet()) {
          RoleMap roleMap = map.getValue();
          writer.startNode("roleMap");
          writer.addAttribute("type", map.getKey());

          for(Map.Entry<Role, Set<String>> grantedRole : roleMap.getGrantedRoles().entrySet()) {
            Role role = grantedRole.getKey();
            if(role != null) {
              writer.startNode("role");
              writer.addAttribute("name", role.getName());
              writer.addAttribute("pattern", role.getPattern().pattern());

              writer.startNode("permissions");
              for(Permission permission : role.getPermissions()) {
                writer.startNode("permission");
                writer.setValue(permission.getId());
                writer.endNode();
              }
              writer.endNode();

              writer.startNode("assignedSIDs");
              for(String sid : grantedRole.getValue()) {
                writer.startNode("sid");
                writer.setValue(sid);
                writer.endNode();
              }
              writer.endNode();

              writer.endNode();
            }
          }
          writer.endNode();
        }
      }

      public Object unmarshal(HierarchicalStreamReader reader, final UnmarshallingContext context) {
        RoleBasedAuthorizationStrategy strategy = create();

        while(reader.hasMoreChildren()) {
          reader.moveDown();
          if(reader.getNodeName().equals("roleMap")) {
            String type = reader.getAttribute("type");
            RoleMap map = new RoleMap();
            while(reader.hasMoreChildren()) {
              reader.moveDown();
              String name = reader.getAttribute("name");
              String pattern = reader.getAttribute("pattern");
              Set<Permission> permissions = new HashSet<Permission>();

              String next = reader.peekNextChild();
              if(next != null && next.equals("permissions")) {
                reader.moveDown();
                while(reader.hasMoreChildren()) {
                  reader.moveDown();
                  Permission p = Permission.fromId(reader.getValue());
                  if (p != null) {
                    permissions.add(p);
                  }
                  reader.moveUp();
                }
                reader.moveUp();
              }

              Role role = new Role(name, pattern, permissions);
              map.addRole(role);

              next = reader.peekNextChild();
              if(next != null && next.equals("assignedSIDs")) {
                reader.moveDown();
                while(reader.hasMoreChildren()) {
                  reader.moveDown();
                  map.assignRole(role, reader.getValue());
                  reader.moveUp();
                }
                reader.moveUp();
              }
              reader.moveUp();
            }
            strategy.grantedRoles.put(type, map);
          }
          reader.moveUp();
        }
        return strategy;
      }

      protected RoleBasedAuthorizationStrategy create() {
          return new RoleBasedAuthorizationStrategy();
      }
  }  

   /**
     * Updates macro roles
     * @since 2.1.0
     */
    void renewMacroRoles()
    {
        //TODO: add mandatory roles
        
        // Check role extensions
        for (UserMacroExtension userExt : UserMacroExtension.all())
        {
            if (userExt.IsApplicable(RoleType.Global))
            {
                getRoleMap(GLOBAL).getSids().contains(userExt.getName());
            }
        }
    }

    /**
     * Control job create using {@link org.jenkinsci.plugins.rolestrategy.RoleBasedProjectNamingStrategy}.
     * @since 2.2.0
     */
    public static boolean isCreateAllowed(){
        return Jenkins.getVersion().isNewerThan(new VersionNumber("1.566"));
    }

  /**
   * Descriptor used to bind the strategy to the Web forms.
   */
  public static final class DescriptorImpl extends GlobalMatrixAuthorizationStrategy.DescriptorImpl {

    @Override
    public  String getDisplayName() {
      return Messages.RoleBasedAuthorizationStrategy_DisplayName();
    }

    /** 
     * Called on role management form's submission.
     */
    public void doRolesSubmit(StaplerRequest req, StaplerResponse rsp) throws UnsupportedEncodingException, ServletException, FormException, IOException {
      Hudson.getInstance().checkPermission(Hudson.ADMINISTER);
      
      req.setCharacterEncoding("UTF-8");
      JSONObject json = req.getSubmittedForm();
      AuthorizationStrategy strategy = this.newInstance(req, json);
      Hudson.getInstance().setAuthorizationStrategy(strategy);
      // Persist the data
      Hudson.getInstance().save();
    }

    /**
     * Called on role assignment form's submission.
     */
    public void doAssignSubmit(StaplerRequest req, StaplerResponse rsp) throws UnsupportedEncodingException, ServletException, FormException, IOException {
      Hudson.getInstance().checkPermission(Hudson.ADMINISTER);
      
      req.setCharacterEncoding("UTF-8");
      JSONObject json = req.getSubmittedForm();
      AuthorizationStrategy oldStrategy = Hudson.getInstance().getAuthorizationStrategy();
      
      if (json.has(GLOBAL) && json.has(PROJECT) && oldStrategy instanceof RoleBasedAuthorizationStrategy) {
        RoleBasedAuthorizationStrategy strategy = (RoleBasedAuthorizationStrategy) oldStrategy;
        Map<String, RoleMap> maps = strategy.getRoleMaps();

        for(Map.Entry<String, RoleMap> map : maps.entrySet()) {        
          // Get roles and skip non-existent role entries (backward-comp)
          RoleMap roleMap = map.getValue();
          roleMap.clearSids();
          JSONObject roles = json.getJSONObject(map.getKey());
          if (roles.isNullObject()) {
              continue;
          }
          
          for(Map.Entry<String,JSONObject> r : (Set<Map.Entry<String,JSONObject>>)roles.getJSONObject("data").entrySet()) {
            String sid = r.getKey();
            for(Map.Entry<String,Boolean> e : (Set<Map.Entry<String,Boolean>>)r.getValue().entrySet()) {
              if(e.getValue()) {
                Role role = roleMap.getRole(e.getKey());
                if(role != null && sid != null && !sid.equals("")) {
                  roleMap.assignRole(role, sid);
                }
              }
            }
          }
        }
        // Persist the data
        Hudson.getInstance().save();
      }
    }

    /**
     * Method called on Hudson Manage panel submission, and plugin specific forms
     * to create the {@link AuthorizationStrategy} object.
     */
    @Override
    public AuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData) throws FormException {
      AuthorizationStrategy oldStrategy = Hudson.getInstance().getAuthorizationStrategy();
      RoleBasedAuthorizationStrategy strategy;

      // If the form contains data, it means the method has been called by plugin
      // specifics forms, and we need to handle it.
      if (formData.has(GLOBAL) && formData.has(PROJECT) && formData.has(SLAVE) && oldStrategy instanceof RoleBasedAuthorizationStrategy) {
        strategy = new RoleBasedAuthorizationStrategy();

        JSONObject globalRoles = formData.getJSONObject(GLOBAL);
        for(Map.Entry<String,JSONObject> r : (Set<Map.Entry<String,JSONObject>>)globalRoles.getJSONObject("data").entrySet()) {
          String roleName = r.getKey();
          Set<Permission> permissions = new HashSet<Permission>();
          for(Map.Entry<String,Boolean> e : (Set<Map.Entry<String,Boolean>>)r.getValue().entrySet()) {
              if(e.getValue()) {
                  Permission p = Permission.fromId(e.getKey());
                  permissions.add(p);
              }
          }

          Role role = new Role(roleName, permissions);
          strategy.addRole(GLOBAL, role);
          RoleMap roleMap = ((RoleBasedAuthorizationStrategy) oldStrategy).getRoleMap(GLOBAL);
          if(roleMap != null) {
            Set<String> sids = roleMap.getSidsForRole(roleName);
            if(sids != null) {
              for(String sid : sids) {
                strategy.assignRole(GLOBAL, role, sid);
              }
            }
          }
        }

        ReadRoles(formData, PROJECT, strategy, (RoleBasedAuthorizationStrategy)oldStrategy);
        ReadRoles(formData, SLAVE, strategy, (RoleBasedAuthorizationStrategy)oldStrategy);
      }
      // When called from Hudson Manage panel, but was already on a role-based strategy
      else if(oldStrategy instanceof RoleBasedAuthorizationStrategy) {
        // Do nothing, keep the same strategy
        strategy = (RoleBasedAuthorizationStrategy) oldStrategy;
      }
      // When called from Hudson Manage panel, but when the previous strategy wasn't
      // role-based, it means we need to create an admin role, and assign it to the
      // current user to not throw him out of the webapp
      else {
        strategy = new RoleBasedAuthorizationStrategy();
        Role adminRole = createAdminRole();
        strategy.addRole(GLOBAL, adminRole);
        strategy.assignRole(GLOBAL, adminRole, getCurrentUser());
      }
      strategy.renewMacroRoles();
      return strategy;
    }

    private void ReadRoles(JSONObject formData, String roleType,
            RoleBasedAuthorizationStrategy targetStrategy, RoleBasedAuthorizationStrategy oldStrategy)
    {     
        if (!formData.has(roleType)) {
            assert false : "Unexistent Role type " + roleType;
            return;
        }
        JSONObject projectRoles = formData.getJSONObject(roleType);
        if (!projectRoles.containsKey("data")) {
            assert false : "No data at role description";
            return;
        }
        
        for(Map.Entry<String,JSONObject> r : (Set<Map.Entry<String,JSONObject>>)projectRoles.getJSONObject("data").entrySet()) {
          String roleName = r.getKey();
          Set<Permission> permissions = new HashSet<Permission>();
          String pattern = r.getValue().getString("pattern");
          if(pattern != null) {
            r.getValue().remove("pattern");
          }
          else {
            pattern = ".*";
          }
          for(Map.Entry<String,Boolean> e : (Set<Map.Entry<String,Boolean>>)r.getValue().entrySet()) {
              if(e.getValue()) {
                  Permission p = Permission.fromId(e.getKey());
                  permissions.add(p);
              }
          }

          Role role = new Role(roleName, pattern, permissions);
          targetStrategy.addRole(roleType, role);

          RoleMap roleMap = oldStrategy.getRoleMap(roleType);
          if(roleMap != null) {
            Set<String> sids = roleMap.getSidsForRole(roleName);
            if(sids != null) {
              for(String sid : sids) {
                targetStrategy.assignRole(roleType, role, sid);
              }
            }
          }
        }
    }
    
    /**
     * Create an admin role.
     */
    private Role createAdminRole() {
      Set<Permission> permissions = new HashSet<Permission>();
      for(PermissionGroup group : getGroups(GLOBAL)) {
        for(Permission permission : group) {
          permissions.add(permission);
        }
      }
      Role role = new Role("admin", permissions);
      return role;
    }

    /**
     * Get the current user ({@code Anonymous} if not logged-in).
     * @return Sid of the current user
     */
    private String getCurrentUser() {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getCurrentUser(): start");
      PrincipalSid currentUser = new PrincipalSid(Hudson.getAuthentication());
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getCurrentUser(): return currentUser.getPrincipal()={0}", currentUser.getPrincipal());
      return currentUser.getPrincipal();
    }

    /**
     * Get the needed permissions groups.
     */
    public List<PermissionGroup> getGroups(String type) {
        LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): start", type);
        List<PermissionGroup> groups;
        if(type.equals(GLOBAL)) {
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups=PermissionGroup.getAll()", type);
            groups = new ArrayList<PermissionGroup>(PermissionGroup.getAll());
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Permission.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Permission.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
        }
        else if(type.equals(PROJECT)) {
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups=PermissionGroup.getAll()", type);
            groups = new ArrayList<PermissionGroup>(PermissionGroup.getAll());
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Permission.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Permission.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Hudson.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Hudson.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Computer.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Computer.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(View.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(View.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
        }
        else if (type.equals(SLAVE)) {
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups=PermissionGroup.getAll()", type);
            groups = new ArrayList<PermissionGroup>(PermissionGroup.getAll());
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Permission.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Permission.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Hudson.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Hudson.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(View.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(View.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            
            // Project, SCM and Run permissions 
            groups.remove(PermissionGroup.get(Item.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Item.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(SCM.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(SCM.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
            groups.remove(PermissionGroup.get(Run.class));
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): groups.remove(Run.class)", type);
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups={1}", new Object[] {type, groups});
        }
        else {
            LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): goups=null", type);
            groups = null;
        }
        LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.getGroups(type={0}): return goups={1}", new Object[] {type, groups});
        return groups;
    }

    /**
     * Check if the permission should be displayed.
     */
    public boolean showPermission(String type, Permission p) {
      LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.showPermission(type={0}, p={1}): start", new Object[] {type, p});
      if(type.equals(GLOBAL)) {
        LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.showPermission(type={0}, p={1}): return showPermission(Permission)", new Object[] {type, p});
        return showPermission(p);
      }
      else if(type.equals(PROJECT)) {
        LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.showPermission(type={0}, p={1}): return p == Item.CREATE && isCreateAllowed() && p.getEnabled() || p != Item.CREATE && p.getEnabled()", new Object[] {type, p});
        return p == Item.CREATE && isCreateAllowed() && p.getEnabled() || p != Item.CREATE && p.getEnabled();
      }
      else if (type.equals(SLAVE)) {
          LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.showPermission(type={0}, p={1}): return p!=Computer.CREATE && p.getEnabled()", new Object[] {type, p});
          return p!=Computer.CREATE && p.getEnabled();
      }
      else {
        LOGGER.log(Level.INFO, "OUT: RoleBasedAuthorizationStrategy.DescriptorImpl.showPermission(type={0}, p={1}): return false", new Object[] {type, p});
        return false;
      }
    }
  }
}
