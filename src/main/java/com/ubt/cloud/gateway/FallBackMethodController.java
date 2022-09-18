package com.ubt.cloud.gateway;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FallBackMethodController {

    @GetMapping("/backendServiceFallBack")
    public String backendServiceFallBackMethod() {
        return "Backend Service is taking longer than Expected." +
                " Please try again later";
    }

    @GetMapping("/emailsServiceFallBack")
    public String emailsServiceFallBackMethod() {
        return "Emails Service is taking longer than Expected." +
                " Please try again later";
    }

    @GetMapping("/authServiceFallBack")
    public String authServiceFallBackMethod() {
        return "Auth Service is taking longer than Expected." +
                " Please try again later";
    }
}
