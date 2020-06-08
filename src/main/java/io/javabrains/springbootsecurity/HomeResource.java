package io.javabrains.springbootsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeResource {

    @GetMapping("/")
    public String home() {
        return ("<h1>Welcome</h1>");
    }

    @GetMapping("/user")
    public String user() {
        printPrincipal();
        return ("<h1>Welcome User</h1>");

    }

    @GetMapping("/admin")
    public String admin() {
        printPrincipal();
        return ("<h1>Welcome Admin</h1>");
    }

    @GetMapping("/playful")
    public String playful() {
        return ("<h1>Welcome Playful</h1>");
    }

    public void printPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        User user = (User) principal;
        System.out.printf("principal = %s", user);

    }
}
