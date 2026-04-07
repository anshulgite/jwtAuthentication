package com.jwtAuthentication.common;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Base64;

public class Validators {

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    public static boolean isValidEmail(String email) {
     try {
      //validate email
      String emailRegex = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@" +
                          "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})+";
        if (email.matches(emailRegex)) {
            return true;
        } else {
            throw new RuntimeException("Invalid email");
        }
     } catch (Exception e) {
       throw new RuntimeException("Failed to validate email");
     }
    }

    //validate phone
    public static boolean isValidPhone(String phone) {
     try {
      String phoneRegex = "^[+]?[0-9]{10,15}$";
      if (phone != null && phone.matches(phoneRegex)) {
        return true;
      } else {
        throw new RuntimeException("Invalid phone");
      }
     } catch (Exception e) {
      throw new RuntimeException("Failed to validate phone");
     }
    }

    public static String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

}
