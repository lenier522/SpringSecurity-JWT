# 🔒 Spring Security JWT

Este proyecto implementa autenticación segura en una API REST con Spring Boot, utilizando JSON Web Tokens (JWT) para la gestión de sesiones y protección de endpoints.

## 🚀 Características Principales

- **Autenticación Segura**: Sistema de login/registro con tokens JWT y refresh tokens.
- **Protección de Endpoints**: Configuración personalizable de seguridad para rutas protegidas.
- **Gestión de Tokens**: Revocación de tokens y manejo de expiración automática.

## ⚙️ Configuración Rápida

```bash
# Clonar repositorio
git clone https://github.com/lenier522/SpringSecurity-JWT

# Configurar variables en application.yml
application:
  security:
    jwt:
      secret-key: clave-secreta
      expiration: 86400000 # 1 día
```

## 🔗 Endpoints Clave

| Método | Ruta             | Descripción                      |
| ------ | ---------------- | -------------------------------- |
| POST   | `/auth/register` | Registro de nuevos usuarios      |
| POST   | `/auth/login`    | Autenticación y obtención de JWT |
| GET    | `/api/protegido` | Endpoint de ejemplo protegido    |

## 🧩 Tecnologías Utilizadas

- **Spring Boot 3.x**: Framework principal para el desarrollo de la API.
- **Spring Security**: Manejo de autenticación y autorización.
- **JJWT**: Implementación de JSON Web Tokens.

