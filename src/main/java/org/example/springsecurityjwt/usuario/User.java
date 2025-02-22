package org.example.springsecurityjwt.usuario;

import jakarta.persistence.*;
import org.example.springsecurityjwt.repository.Token;
import java.util.List;
import java.util.ArrayList;


@Entity(name = "users")
public class User {

    @Id
    @GeneratedValue
    private Long id;

    private String name;

    @Column(unique = true)
    private String email;

    private String password;

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<Token> tokens = new ArrayList<>();

    // Métodos getter y setter manuales
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<Token> getTokens() {
        return tokens;
    }

    public void setTokens(List<Token> tokens) {
        this.tokens = tokens;
    }

    // Método estático para crear un Builder
    public static Builder builder() {
        return new Builder();
    }

    // Clase Builder interna
    public static class Builder {
        private Long id;
        private String name;
        private String email;
        private String password;
        private List<Token> tokens;

        public Builder id(Long id) {
            this.id = id;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder tokens(List<Token> tokens) {
            this.tokens = tokens;
            return this;
        }

        public User build() {
            User user = new User();
            user.setId(this.id);
            user.setName(this.name);
            user.setEmail(this.email);
            user.setPassword(this.password);
            user.setTokens(this.tokens != null ? this.tokens : new ArrayList<>());
            return user;
        }
    }
}