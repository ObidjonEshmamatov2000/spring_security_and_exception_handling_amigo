package uz.mafia.springsecurityamigoscode.auth;

import org.springframework.stereotype.Repository;
import uz.mafia.springsecurityamigoscode.auth.ApplicationUser;

import java.util.Optional;

@Repository
public interface ApplicationUserDao {
    Optional<ApplicationUser> findApplicationUserByUsername(String username);
}
