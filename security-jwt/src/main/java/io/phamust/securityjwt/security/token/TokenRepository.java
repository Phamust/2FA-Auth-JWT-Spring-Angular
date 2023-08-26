package io.phamust.securityjwt.security.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token,Long> {
    @Query("SELECT t FROM Token t INNER JOIN t.user u " +
            "WHERE u.id = :id AND (t.expired = false OR t.revoked = false)")
    List<Token> findAllValidTokenByUser(@Param("id") Integer id);

    Optional<Token> findByToken(String token);
}
