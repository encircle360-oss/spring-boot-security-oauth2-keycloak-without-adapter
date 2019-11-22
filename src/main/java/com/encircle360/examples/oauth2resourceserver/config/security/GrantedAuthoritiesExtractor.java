package com.encircle360.examples.oauth2resourceserver.config.security;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Extracts keycloak realm roles, client roles (scopes) and composite roles
 * (client scoped user roles) from a keycloak jwt token.
 *
 * @author Patrick Huetter
 */
public class GrantedAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Value("${resourceServer.resourceId}")
    private String resourceId;

    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // get roles of user for current/this resource
        if (jwt.containsClaim("resource_access")) {
            JSONObject resourceAccess = (JSONObject) jwt.getClaims().get("resource_access");
            if (resourceAccess.containsKey(this.resourceId)) {
                JSONArray resourceRoles = (JSONArray) ((JSONObject) resourceAccess.get(this.resourceId)).get("roles");
                for (Object resourceRole : resourceRoles) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + resourceRole.toString().toUpperCase()));
                }
            }
        }

        // get realm roles of user
        if (jwt.containsClaim("realm_access")) {
            JSONObject realmAccess = (JSONObject) jwt.getClaims().get("realm_access");
            if (realmAccess.containsKey("roles")) {
                JSONArray realmRoles = (JSONArray) realmAccess.get("roles");
                for (Object realmRole : realmRoles) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + realmRole.toString().toUpperCase()));
                }
            }
        }

        // get scopes (client roles) for current client/resource
        if (jwt.containsClaim("scope")) {
            String scope = (String) jwt.getClaims().get("scope");
            if (!scope.isBlank() && !scope.isEmpty()) {
                String[] scopes = scope.split("\\s");
                for (String scopeAuthority : scopes) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scopeAuthority.toUpperCase()));
                }
            }
        }

        return authorities;
    }
}
