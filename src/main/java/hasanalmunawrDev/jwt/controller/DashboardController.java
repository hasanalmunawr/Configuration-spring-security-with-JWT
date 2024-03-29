package hasanalmunawrDev.jwt.controller;


import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping(path = "/api")
public class DashboardController {

//    @PreAuthorize("hasAnyRole('MANAGER, ADMIN, USER')") // ERROR
//    @GetMapping("/welcome-message")
//    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication){
//        return ResponseEntity.ok("Welcome to the JWT Tutorial:"+authentication.getName()+"with scope:"+authentication.getAuthorities());
//    }
//
//    @PreAuthorize("hasRole('MANAGER')")
//    @GetMapping("/manager-message")
//    public ResponseEntity<String> getManagerData(Principal principal){
//        return ResponseEntity.ok("Manager : "+principal.getName());
//
//    }
//
//    @PreAuthorize("hasRole('ADMIN')")
//    @PostMapping("/admin-message")
//    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal){
//        return ResponseEntity.ok("Admin::"+principal.getName()+" has this message:"+message);
//
//    }

//        @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_USER')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication) {
        return ResponseEntity.ok("Welcome to the JWT Tutorial:" + authentication.getName() + "with scope:" + authentication.getAuthorities());
    }

//        @PreAuthorize("hasRole('ROLE_MANAGER')")
    @PreAuthorize("hasAnyAuthority('SCOPE_READ', 'SCOPE_WRITE')")
    @GetMapping("/manager-message")
    public ResponseEntity<String> getManagerData(Principal principal) {
        return ResponseEntity.ok("Manager::" + principal.getName());

    }

//        @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('SCOPE_READ', 'SCOPE_WRITE', 'SCOPE_DELETE)")
    @PostMapping("/admin-message")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal) {
        return ResponseEntity.ok("Admin::" + principal.getName() + " has this message:" + message);

    }

}
