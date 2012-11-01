package com.nedap.soul.cassandra.auth;

import com.nedap.soul.cassandra.auth.pbkdf2.PasswordGenerator;
import java.io.Console;

public class Generator {

    public static void main(String[] args) throws Exception {
        Console cons = System.console();
        if(cons != null) {
            char[] s = cons.readPassword();
            if(s.length > 0) {
                PasswordGenerator generator = new PasswordGenerator();
                System.out.println(generator.hash(s));
            } else {
                throw new RuntimeException("No password given");
            }
        } else {
            throw new RuntimeException("Can't get console");
        }
    }
}