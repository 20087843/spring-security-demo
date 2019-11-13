package cn.pri.smilly.springwebsecurity.service;

import cn.pri.smilly.springwebsecurity.domain.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MemoryUserDetailService implements UserDetailsService {
    private List<User> userCache = new ArrayList<>();

    public void saveUser(User user){
        userCache.add(user);
    }

    public void deleteUser(User user){
        userCache.remove(user);
    }

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        return userCache.stream().filter(user -> user.getUsername().equals(username)).findFirst().orElseGet(null);
    }
}
