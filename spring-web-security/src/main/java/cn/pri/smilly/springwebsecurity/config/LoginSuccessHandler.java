package cn.pri.smilly.springwebsecurity.config;

import cn.pri.smilly.springwebsecurity.common.TokenComponent;
import cn.pri.smilly.springwebsecurity.service.MemoryUserDetailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    private MemoryUserDetailService userDetailsService;
    @Autowired
    private TokenComponent tokenComponent;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        final String token = tokenComponent.generateToken(userDetails);
        handleRequest(request, response, token);
        clearAuthenticationAttributes(request);
        log.info(userDetails.getUsername() + " with role " + userDetails.getAuthorities() + " logged in");
    }

    protected void handleRequest(HttpServletRequest request, HttpServletResponse response, String token) throws IOException {
        if (response.isCommitted()) {
            log.debug("Response has already been committed.");
            return;
        }

        // write token to client
        response.addHeader(TokenComponent.REQUEST_TOKEN_HEADER, TokenComponent.REQUEST_TOKEN_HEAD + token);
        try (PrintWriter writer = response.getWriter()) {
            writer.write(token);
            writer.flush();
        }
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
