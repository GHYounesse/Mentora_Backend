package com.app.mentora;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Base64;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;

@SpringBootApplication
public class MentoraApplication {

	public static void main(String[] args) {


//		SecretKey key = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);
//		System.out.println("Secret Key:"+Base64.getEncoder().encodeToString(key.getEncoded()));

		SpringApplication.run(MentoraApplication.class, args);
	}

}
