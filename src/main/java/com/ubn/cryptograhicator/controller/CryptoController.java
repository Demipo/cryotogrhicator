package com.ubn.cryptograhicator.controller;

import com.ubn.cryptograhicator.dto.EncryptionResult;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Controller
public class CryptoController {

    private static final String SECRET_KEY = "YourSecretKey123";

    @GetMapping("/")
    public String showConverterPage() {
        return "crypto-converter";
    }

    @PostMapping("/convert")
    public String convertText(
            @RequestParam("type") String type,
            @RequestParam("input") String input,
            Model model
    ) {
        String result;
        String iv = null;
        try {
            switch (type) {
                case "encrypt":
                    EncryptionResult encryptionResult = encrypt(input);
                    result = encryptionResult.getEncryptedText();
                    iv = encryptionResult.getIv();
                    break;
                case "encode":
                    result = encode(input);
                    break;
                case "hash":
                    result = hash(input);
                    break;
                default:
                    result = "Invalid conversion type";
            }
        } catch (Exception e) {
            result = "Error processing conversion";
        }
        model.addAttribute("result", result);
        model.addAttribute("iv", iv);
        return "crypto-converter";
    }

    private EncryptionResult encrypt(String input) throws Exception {
        byte[] iv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return new EncryptionResult(Base64.getEncoder().encodeToString(combined), Base64.getEncoder().encodeToString(iv));
    }

    private String encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private String hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encodedhash);
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
