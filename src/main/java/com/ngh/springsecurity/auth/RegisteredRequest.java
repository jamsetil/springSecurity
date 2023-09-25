package com.ngh.springsecurity.auth;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisteredRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;

}
