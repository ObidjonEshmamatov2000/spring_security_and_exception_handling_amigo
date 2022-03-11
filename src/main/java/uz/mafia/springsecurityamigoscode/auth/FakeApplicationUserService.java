package uz.mafia.springsecurityamigoscode.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import uz.mafia.springsecurityamigoscode.security.ApplicationUserRole;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static uz.mafia.springsecurityamigoscode.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserService implements ApplicationUserDao{
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> findApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Arrays.asList(
          new ApplicationUser(
                  "star",
                  passwordEncoder.encode("star"),
                  STUDENT.getGrantedAuthorities(),
                  true,
                  true,
                  true,
                  true
          ), new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("linda"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
        new ApplicationUser(
                "tom",
                passwordEncoder.encode("tom"),
                ADMIN_TRAINEE.getGrantedAuthorities(),
                true,
                true,
                true,
                true
        )
        );

        return applicationUsers;
    }
}
