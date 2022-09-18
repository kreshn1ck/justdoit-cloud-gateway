package com.ubt.cloud.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableHystrix
public class GatewayConfig {

    @Autowired
    JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("AUTH-SERVICE", r -> r.path("/auth/**")
                        .filters(f -> f.filter(jwtTokenAuthenticationFilter))
                        .uri("lb://AUTH-SERVICE"))

                .route("BACKEND-SERVICE", r -> r.path("/backend/**")
                        .filters(f -> f.filter(jwtTokenAuthenticationFilter))
                        .uri("lb://BACKEND-SERVICE"))

                .route("EMAILS-SERVICE", r -> r.path("/emails/**")
                        .filters(f -> f.filter(jwtTokenAuthenticationFilter))
                        .uri("lb://EMAILS-SERVICE"))
                .build();
    }

}
