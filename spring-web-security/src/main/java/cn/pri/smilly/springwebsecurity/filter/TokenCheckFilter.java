package cn.pri.smilly.springwebsecurity.filter;

import cn.pri.smilly.springwebsecurity.common.TokenComponent;
import cn.pri.smilly.springwebsecurity.domain.User;
import cn.pri.smilly.springwebsecurity.service.MemoryUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class TokenCheckFilter extends GenericFilterBean {
    @Autowired
    private MemoryUserDetailService userDetailsService;
    @Autowired
    private TokenComponent tokenComponent;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = tokenComponent.parseTokenFromRequest((HttpServletRequest) request);
        if (!StringUtils.isEmpty(token)) {
            String username = tokenComponent.parserUsernameFromToken(token);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userDetailsService.loadUserByUsername(username);
                if (tokenComponent.validateToken(token, user)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails((HttpServletRequest) request));
                    SecurityContextHolder.getContext().setAuthentication(authentication); //设置用户登录状态
                }
            }
        }
        chain.doFilter(request, response);
    }

}
