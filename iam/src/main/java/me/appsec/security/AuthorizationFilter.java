package me.appsec.security;

import jakarta.annotation.Priority;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.lang.reflect.Method;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {
    @Context
    private ResourceInfo resourceInfo;
    @Override
    public void filter(ContainerRequestContext requestContext){
        Method method = resourceInfo.getResourceMethod();

        // @DenyAll on the method takes precedence over @RolesAllowed and @PermitAll
        if(method.isAnnotationPresent(DenyAll.class)){
            refuseRequest();
        }

        // @RolesAllowed on the method takes precedence over @PermitAll
        RolesAllowed rolesAllowed = method.getAnnotation(RolesAllowed.class);
        if (rolesAllowed != null){
            performAuthorization(rolesAllowed.value(),requestContext);
            return;
        }

        // @PermitAll on the method takes precedence over @RolesAllowed on the class
        if(method.isAnnotationPresent(PermitAll.class)){
            // Do nothing
            return;
        }
        // @PermitAll must not be attached to classes

        // @RolesAllowed on the class takes precedence over @PermitAll on the class
        rolesAllowed = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);
        if (rolesAllowed != null) {
            performAuthorization(rolesAllowed.value(), requestContext);
            return;
        }

        // @DenyAll on the class
        if (resourceInfo.getResourceClass().isAnnotationPresent(DenyAll.class)) {
            refuseRequest();
        }
        // Authorization is not required for non-annotated methods
    }
    /*
     * Perform authorization based on roles.
     *
     * @param rolesAllowed the allowed roles
     * @param requestContext the request context
     */
    private void performAuthorization(String[] rolesAllowed, ContainerRequestContext requestContext) {
        if (rolesAllowed.length > 0 && !isAuthenticated(requestContext)) {
            refuseRequest();
        }
        for (final String role : rolesAllowed){
            if(requestContext.getSecurityContext().isUserInRole(role)){
                return;
            }
        }
        refuseRequest();
    }
    private boolean isAuthenticated(final ContainerRequestContext requestContext) {
        // Return true if the user is authenticated or false otherwise
        return requestContext.getSecurityContext().getUserPrincipal() != null;
    }
    private void refuseRequest() {
        throw new WebApplicationException("You don't have permissions to perform this action.", Response.Status.UNAUTHORIZED);
    }
}
