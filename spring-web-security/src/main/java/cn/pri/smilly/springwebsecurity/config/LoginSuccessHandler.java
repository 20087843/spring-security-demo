package cn.pri.smilly.springwebsecurity.config;

import cn.pri.smilly.springwebsecurity.common.TokenComponent;
import cn.pri.smilly.springwebsecurity.service.MemoryUserDetailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
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
        String targetUrl = "/home";
        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        redirectStrategy.sendRedirect(request, response, targetUrl + "?token=" + token);
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
