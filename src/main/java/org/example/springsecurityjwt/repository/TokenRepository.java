package org.example.springsecurityjwt.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends CrudRepository<Token, Long> {

    // Busca todos los tokens válidos y no revocados para un usuario específico
    List<Token> findAllValidIsFalseOrRevokedIsfalseByuserId(Long id);
    // Busca un token por su valor (campo token)
    Optional<Token> findByToken(String token);
}
