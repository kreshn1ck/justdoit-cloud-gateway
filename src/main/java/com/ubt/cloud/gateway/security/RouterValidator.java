package com.ubt.cloud.gateway.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouterValidator {

    private static final List<String> openApiEndpoints = List.of(
            "/auth/login",
            "/auth/refresh-token/",
            "/auth/users/reset-password/",
            "/auth/users/",
            "/auth/users/user-confirmation",
            "/auth/users/sign-up",
            "/emails/forgot-password"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints
                    .stream()
                    .noneMatch(uri -> request.getURI().getPath().startsWith(uri));

}
