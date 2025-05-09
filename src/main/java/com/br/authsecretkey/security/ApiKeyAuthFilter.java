package com.br.authsecretkey.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    @Value("${api.secret.key}")
    private String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String apiKey = request.getHeader("X-API-SECRET");

        System.out.println("🔍 Chave recebida: " + apiKey);
        System.out.println("🔐 Chave configurada: " + secretKey);

        if (apiKey == null || !apiKey.trim().equals(secretKey.trim())) {
            System.out.println("❌ Chave inválida!");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Unauthorized - Invalid API Key");
            return;
        }

        System.out.println("✅ Chave válida!");
        filterChain.doFilter(request, response);
    }
}