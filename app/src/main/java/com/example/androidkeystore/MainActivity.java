package com.example.androidkeystore;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    EditText edtPassword;
    Button btnExe;
    private String mAlias = "ECOQOLO";
    private boolean isEncrypt = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            KeyStoreUtils.createKeys(this, mAlias);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        initViews();
    }

    private void initViews() {
        edtPassword = findViewById(R.id.edtPassword);
        btnExe = findViewById(R.id.btnExe);
        btnExe.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String text = edtPassword.getText().toString();
                    KeyPair keyPair = KeyStoreUtils.getAndroidKeyStoreKeyPair(mAlias);
                    if (keyPair != null) {
                        if (isEncrypt) {
                            String encyptedString = CipherWrapper.encrypt(text, keyPair.getPublic());
                            edtPassword.setText(encyptedString);
                            System.out.println(encyptedString);
                        } else {
                            String decyptedString = CipherWrapper.decrypt(text, keyPair.getPrivate());
                            edtPassword.setText(decyptedString);
                            System.out.println(decyptedString);
                        }
                        isEncrypt = !isEncrypt;
                    }
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
