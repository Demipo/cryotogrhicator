package com.ubn.cryptograhicator.dto;

public class EncryptionResult {
    private String encryptedText;
    private String iv;

    public EncryptionResult(String encryptedText, String iv) {
        this.encryptedText = encryptedText;
        this.iv = iv;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public void setEncryptedText(String encryptedText) {
        this.encryptedText = encryptedText;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
