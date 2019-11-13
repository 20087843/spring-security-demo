package cn.pri.smilly.springwebsecurity.contorller;

import cn.pri.smilly.springwebsecurity.common.TokenComponent;
import cn.pri.smilly.springwebsecurity.service.MemoryUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
@RequestMapping
public class UserController {
    @Autowired
    private MemoryUserDetailService userDetailService;
    @Autowired
    private TokenComponent tokenComponent;

    @GetMapping("/")
    public String index() {
        return "/login";
    }

    @GetMapping("/token/refresh")
    public String tokenRefresh(HttpServletRequest request) {
        String token = tokenComponent.parseTokenFromRequest(request);
        return tokenComponent.refreshToken(token);
    }

    @GetMapping("/home")
    public String home() {
        return "welcome, you have been successful stated security leaning !";
    }

    @GetMapping("/current")
    public Principal current(Principal principal) {
        return principal;
    }

    @GetMapping("/user")
    public String user() {
        return "this is user authenticated home page !";
    }

    @GetMapping("/user/detail")
    public UserDetails userDetail(Principal principal) {
        return userDetailService.loadUserByUsername(principal.getName());
    }

    @GetMapping("/admin")
    public String admin() {
        return "this is admin authenticated home page !";
    }

    @GetMapping("/admin/manage")
    public String adminManage() {
        return "this is admin management page !";
    }
}
