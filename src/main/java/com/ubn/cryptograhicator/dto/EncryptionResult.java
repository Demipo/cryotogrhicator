package com.ubn.cryptograhicator.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EncryptionResult {
    private String encryptedText;
    private String secret;
}
