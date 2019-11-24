package io.akoserwa.SecureKeycloakApp.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@RestController
public class TokenController {


    @RequestMapping("/token")
    public String getToken() {
        return JWTUtil.getJWTToken();
    }

    @RequestMapping("/logout")
    public String clear(HttpServletRequest request, HttpServletResponse response) {
        try {
            request.logout();
        } catch (ServletException e) {
            e.printStackTrace();
        }
        return "logout";
    }

}
