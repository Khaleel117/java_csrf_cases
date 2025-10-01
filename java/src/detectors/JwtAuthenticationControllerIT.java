package com.meepleconnect.boardgamesapi.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.meepleconnect.boardgamesapi.exceptions.BadRequestException;
import com.meepleconnect.boardgamesapi.security.JwtRequest;
import com.meepleconnect.boardgamesapi.security.JwtResponse;
import com.meepleconnect.boardgamesapi.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import com.meepleconnect.boardgamesapi.entities.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.Optional;
import java.util.Arrays;
import com.meepleconnect.boardgamesapi.entities.Role;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(JwtAuthenticationController.class)
@TestPropertySource(properties = {
                "spring.security.csrf.enabled=false",
                "spring.security.user.name=test",
                "spring.security.user.password=test"
})
public class JwtAuthenticationControllerIT {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @MockBean
        private AuthenticationManager authenticationManager;

        @MockBean
        private JwtUtil jwtUtil;

        @MockBean
        private UserDetailsService userDetailsService;

        @MockBean
        private com.meepleconnect.boardgamesapi.repositories.UserRepository userRepository;

        @MockBean
        private com.meepleconnect.boardgamesapi.repositories.RoleRepository roleRepository;

        @MockBean
        private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;


        @Test
        @WithMockUser
        void login_WithValidCredentials_ShouldReturnJwtToken() throws Exception {
                JwtRequest request = new JwtRequest("testuser", "testpass");
                UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                        "testuser", "testpass", new ArrayList<>());
                String expectedToken = "test.jwt.token";

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenReturn(new UsernamePasswordAuthenticationToken(userDetails, null,
                                                new ArrayList<>()));
                when(userDetailsService.loadUserByUsername("testuser")).thenReturn(userDetails);
                when(jwtUtil.generateToken("testuser")).thenReturn(expectedToken);

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                                .andExpect(jsonPath("$.token").value(expectedToken));
        }

        @Test
        @WithMockUser
        void login_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
                JwtRequest request = new JwtRequest("testuser", "wrongpass");

                when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                                .thenThrow(new BadCredentialsException("Bad credentials"));

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @WithMockUser
        void login_WithEmptyUsername_ShouldReturnBadRequest() throws Exception {
                JwtRequest request = new JwtRequest("", "testpass");

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void login_WithEmptyPassword_ShouldReturnBadRequest() throws Exception {
                JwtRequest request = new JwtRequest("testuser", "");

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void login_WithNullUsername_ShouldReturnBadRequest() throws Exception {
        
                JwtRequest request = new JwtRequest(null, "testpass");

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void login_WithNullPassword_ShouldReturnBadRequest() throws Exception {
                JwtRequest request = new JwtRequest("testuser", null);

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void login_WithMissingContentType_ShouldReturnUnsupportedMediaType() throws Exception {
                JwtRequest request = new JwtRequest("testuser", "testpass");

                mockMvc.perform(post("/api/auth/login")
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isUnsupportedMediaType());
        }

        @Test
        void login_WithNullAuthenticationRequest_ShouldThrowBadRequestException() {
                JwtAuthenticationController controller = new JwtAuthenticationController(
                        authenticationManager, jwtUtil, userDetailsService, userRepository, roleRepository, passwordEncoder);


                assertThatThrownBy(() -> controller.createAuthenticationToken(null))
                                .isInstanceOf(BadRequestException.class)
                                .hasMessage("Request body cannot be null");
        }

        @TestConfiguration
        static class PermissiveSecurityConfig {
                @Bean
                public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
                        http
                                        .csrf(csrf -> csrf.disable())
                                        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
                        return http.build();
                }
        }
        @Test
        @WithMockUser
        void registerUser_WithValidData_ShouldReturnCreated() throws Exception {
                String json = """
            {
              "username": "newuser",
              "email": "newuser@example.com",
              "password": "secure123"
            }
            """;

                when(userRepository.findByUserName("newuser")).thenReturn(Optional.empty());

                Role userRole = new Role();
                userRole.setId(1L);
                userRole.setRoleName("ROLE_USER");
                when(roleRepository.findByRoleNameIn(any())).thenReturn(Arrays.asList(userRole));
                when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                        User u = invocation.getArgument(0);
                        u.setId(123L);
                        return u;
                });

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.id").value(123))
                        .andExpect(jsonPath("$.username").value("newuser"))
                        .andExpect(jsonPath("$.message").value("User registered successfully"));
        }

        @Test
        @WithMockUser
        void registerUser_WithEmptyUsername_ShouldReturnBadRequest() throws Exception {
                String json = """
            {
              "username": " ",
              "email": "test@example.com",
              "password": "pass"
            }
            """;

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void registerUser_WithEmptyPassword_ShouldReturnBadRequest() throws Exception {
                String json = """
            {
              "username": "testuser",
              "email": "test@example.com",
              "password": ""
            }
            """;

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser
        void registerUser_WithExistingUsername_ShouldReturnConflict() throws Exception {
                String json = """
            {
              "username": "existinguser",
              "email": "test@example.com",
              "password": "pass"
            }
            """;

                when(userRepository.findByUserName("existinguser")).thenReturn(Optional.of(new User()));

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isConflict());
        }

        @Test
        @WithMockUser
        void registerUser_WhenUnexpectedExceptionOccurs_ShouldReturnInternalServerError() throws Exception {
                String json = """
            {
              "username": "newuser",
              "email": "test@example.com",
              "password": "pass"
            }
            """;

                when(userRepository.findByUserName("newuser")).thenReturn(Optional.empty());
                when(roleRepository.findByRoleNameIn(any())).thenThrow(new RuntimeException("DB down"));

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isInternalServerError());
        }
        @Test
        @WithMockUser
        void registerUser_WithNullUsername_ShouldReturnBadRequest() throws Exception {
                String json = """
        {
          "email": "nulluser@example.com",
          "password": "pass"
        }
        """;

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isBadRequest());
        }
        @Test
        @WithMockUser
        void registerUser_WithNullPassword_ShouldReturnBadRequest() throws Exception {
                String json = """
        {
          "username": "nullpassuser",
          "email": "nullpass@example.com"
        }
        """;

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isBadRequest());
        }
        @Test
        @WithMockUser
        void registerUser_WithNoExistingRole_ShouldCreateAndAssignNewRole() throws Exception {
                String json = """
        {
          "username": "freshuser",
          "email": "freshuser@example.com",
          "password": "password123"
        }
        """;

                when(userRepository.findByUserName("freshuser")).thenReturn(Optional.empty());
                when(roleRepository.findByRoleNameIn(any())).thenReturn(new ArrayList<>());
                when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> {
                        Role r = invocation.getArgument(0);
                        r.setId(99L);
                        return r;
                });

                when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                        User u = invocation.getArgument(0);
                        u.setId(456L);
                        return u;
                });

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.id").value(456))
                        .andExpect(jsonPath("$.username").value("freshuser"))
                        .andExpect(jsonPath("$.message").value("User registered successfully"));
        }

}