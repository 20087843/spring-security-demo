package cn.pri.smilly.springwebsecurity.common;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenComponent {
    private static final String CLAIM_KEY_USERNAME = "sub";
    private static final String CLAIM_KEY_CREATED = "created";
    private static final String CLAIM_KEY_ROLES = "roles";
    public static final String REQUEST_TOKEN_HEADER = "Authorization";
    public static final String REQUEST_TOKEN_HEAD = "Bearer ";
    public static final String REQUEST_TOKEN_PARAM = "token";

    @Value("${jwt.token.secret}")
    private String secret;
    @Value("${jwt.token.expiration}")
    private long expiration;

    private Map<String, String> tokenStore = new HashMap<>();

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_CREATED, new Date());
        claims.put(CLAIM_KEY_ROLES, userDetails.getAuthorities());
        String token = generateToken(claims);
        tokenStore.put(userDetails.getUsername(), token);
        return token;
    }

    public String parseTokenFromRequest(HttpServletRequest request) {
        String token = request.getParameter(TokenComponent.REQUEST_TOKEN_PARAM);
        String authHeader = request.getHeader(TokenComponent.REQUEST_TOKEN_HEADER);
        if (!StringUtils.isEmpty(authHeader) && authHeader.startsWith(TokenComponent.REQUEST_TOKEN_HEAD)) {
            token = authHeader.substring(TokenComponent.REQUEST_TOKEN_HEAD.length()); //如果header中存在token，则覆盖掉url中的token
        }
        return token;
    }

    public String parserUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public String refreshToken(String token) {
        final Claims claims = getClaimsFromToken(token);
        claims.put(CLAIM_KEY_CREATED, new Date());
        return generateToken(claims);
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = parserUsernameFromToken(token);
        return username.equals(userDetails.getUsername())
                && !isTokenExpired(token)
                && tokenStore.containsKey(username);
    }

    public void releaseToken(String username) {
        tokenStore.remove(username);
    }

    private Date getExpirationDateFromToken(String token) {
        final Claims claims = getClaimsFromToken(token);
        return claims.getExpiration();
    }

    private Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

}
