package com.piggymetrics.auth.config;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            return null;
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        Set<String> scopes = new HashSet<>();
        String scope = request.getParameter("scope");
        if (StringUtils.hasText(scope)) {
            for (String s : scope.split(" ")) {
                scopes.add(s);
            }
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("username", username);
        additionalParameters.put("password", password);

        return new PasswordGrantAuthenticationToken(
                username, password, clientPrincipal, scopes, additionalParameters);
    }
}
