#include <iostream>
#include <fstream>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void generateAndSaveParameters(const char* fname_parms, const char* fname_secret_key, const char* fname_ciphertext) {
    // 暗号化パラメータを設定
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // パラメータをファイルに保存
    ofstream spar(fname_parms, ios::out | ios::binary);
    parms.save(spar);
    spar.close();

    // SEALコンテキストを作成
    SEALContext context(parms);

    // キー生成
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // 秘密鍵をファイルに保存
    ofstream ssk(fname_secret_key, ios::out | ios::binary);
    secret_key.save(ssk);
    ssk.close();

    // エンコーダとエンコーダを作成
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);

    // 暗号化するデータを用意（例：実数のベクトル）
    vector<double> data = { 1.0, 2.0, 3.0, 4.0, 5.0 };
    Plaintext plaintext;
    double scale = pow(2.0, 40);
    encoder.encode(data, scale, plaintext);

    // データを暗号化
    Ciphertext ciphertext;
    encryptor.encrypt(plaintext, ciphertext);

    // 暗号文をファイルに保存
    ofstream scipher(fname_ciphertext, ios::out | ios::binary);
    ciphertext.save(scipher);
    scipher.close();

    cout << "パラメータ、秘密鍵、暗号文が生成され、ファイルに保存されました。" << endl;
}

int main() {
    // ファイル名を指定
    const char *fname_parms = "parms";
    const char *fname_secret_key = "secret_key";
    const char *fname_ciphertext = "ciphertext";

    // パラメータ、秘密鍵、および暗号文を生成して保存
    generateAndSaveParameters(fname_parms, fname_secret_key, fname_ciphertext);

    return 0;
}
