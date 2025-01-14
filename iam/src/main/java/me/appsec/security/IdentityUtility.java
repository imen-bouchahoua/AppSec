package me.appsec.security;

import java.util.Set;

public class IdentityUtility {
    private static final ThreadLocal<String> username = new ThreadLocal<>();
    private static final ThreadLocal<Set<String>> roles = new ThreadLocal<>();
    private static final ThreadLocal<String> tenant = new ThreadLocal<>();
    public static void iAm(String username){
        IdentityUtility.username.set(username);
    }

    public static String whoAmI(){
        return username.get();
    }
    public static void setRoles(Set<String> roles){
        IdentityUtility.roles.set(roles);
    }
    public static Set<String> getRoles(){
        return IdentityUtility.roles.get();
    }

    public static void tenantWithName(String tenant){
        IdentityUtility.tenant.set(tenant);
    }

    public static String whichTenant(){
        return IdentityUtility.tenant.get();
    }

}
