package com.vengdom.demo.security;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.net.URLEncoder;
import java.time.Instant;

/**
 * Time-based one-time password support (RFC 6238), implemented directly
 * rather than pulling in a third-party TOTP library - the algorithm itself
 * (HMAC-SHA1 over a 30-second time step, base32-encoded secret) is small
 * and stable enough that it's not worth an extra dependency.
 */
@Service
public class TotpService {

    private static final String ISSUER = "Vingdom";
    private static final int SECRET_BYTES = 20; // 160 bits, standard TOTP secret length
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public String generateSecret() {
        byte[] randomBytes = new byte[SECRET_BYTES];
        new SecureRandom().nextBytes(randomBytes);
        return base32Encode(randomBytes);
    }

    public String buildOtpAuthUri(String secret, String accountEmail) {
        String label = URLEncoder.encode(ISSUER + ":" + accountEmail, StandardCharsets.UTF_8);
        String issuerParam = URLEncoder.encode(ISSUER, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + issuerParam
                + "&algorithm=SHA1&digits=" + CODE_DIGITS + "&period=" + TIME_STEP_SECONDS;
    }

    public boolean verifyCode(String base32Secret, String submittedCode) {
        int code;
        try {
            code = Integer.parseInt(submittedCode.trim());
        } catch (NumberFormatException e) {
            return false;
        }

        byte[] secretBytes = base32Decode(base32Secret);
        long currentStep = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;

        // Allow the immediately adjacent steps too, to tolerate clock drift
        // between the server and whatever device generated the code.
        for (long step = currentStep - 1; step <= currentStep + 1; step++) {
            try {
                if (generateCode(secretBytes, step) == code) {
                    return true;
                }
            } catch (GeneralSecurityException e) {
                return false;
            }
        }
        return false;
    }

    private int generateCode(byte[] secretBytes, long timeStep) throws GeneralSecurityException {
        byte[] data = ByteBuffer.allocate(8).putLong(timeStep).array();
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secretBytes, "HmacSHA1"));
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

        int modulus = (int) Math.pow(10, CODE_DIGITS);
        return binary % modulus;
    }

    private String base32Encode(byte[] data) {
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            result.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return result.toString();
    }

    private byte[] base32Decode(String base32) {
        String cleaned = base32.trim().toUpperCase().replace("=", "");
        int byteCount = cleaned.length() * 5 / 8;
        byte[] result = new byte[byteCount];

        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (char c : cleaned.toCharArray()) {
            int val = BASE32_ALPHABET.indexOf(c);
            if (val < 0) {
                continue;
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result[index++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        return result;
    }
}
