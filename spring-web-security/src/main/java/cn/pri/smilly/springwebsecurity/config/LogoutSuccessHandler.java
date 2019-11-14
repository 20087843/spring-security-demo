package cn.pri.smilly.springwebsecurity.config;

import cn.pri.smilly.springwebsecurity.common.TokenComponent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class LogoutSuccessHandler implements LogoutHandler {
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    @Autowired
    private TokenComponent tokenComponent;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = tokenComponent.parseTokenFromRequest(request);
        String username = tokenComponent.parserUsernameFromToken(token);
        log.info(username + " logged out");
        try {
            redirectStrategy.sendRedirect(request, response, "/");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
