#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "ciphertext-ser.h"
#include <vector>

using namespace lbcrypto;

usint active_clients = 0;

const std::string DATAFOLDER = "demoData";

void RunCKKS();
void update_clients();

//Mock Weights for client 1
std::vector<double> read_data_1(void) {
    std::vector<double> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
    return vectorOfInts1;
}

//Mock Weights for client 2
std::vector<double> read_data_2(void) {
    std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    return vectorOfInts2;
}

//Mock Weights for client 3
std::vector<double> read_data_3(void) {
    std::vector<double> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};
    return vectorOfInts3;
}

class FHEServer {
    public:
        CryptoContext<DCRTPoly> m_serverCC;
        uint numClient = 0;

        void generate_ccontext(int multDepth, int scaleFactorBits, int batchSize) {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(multDepth);
            parameters.SetScalingModSize(scaleFactorBits);
            parameters.SetBatchSize(batchSize);

            m_serverCC = GenCryptoContext(parameters);

            m_serverCC->Enable(PKE);
            m_serverCC->Enable(KEYSWITCH);
            m_serverCC->Enable(LEVELEDSHE);
            m_serverCC->Enable(ADVANCEDSHE);
            m_serverCC->Enable(MULTIPARTY);

            // Output the generated parameters
            std::cout << "p = " << m_serverCC->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
            std::cout << "n = " << m_serverCC->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
            std::cout << "log2 q = " << log2(m_serverCC->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
                    << std::endl;
        }

        void send_ccontext(void) {
            if(!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", m_serverCC, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
            }
        }

        void send_server_public_key(PublicKey<DCRTPoly> pk) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            }
        }

        EvalKey<DCRTPoly> send_key_switch(EvalKey<DCRTPoly> key_switch) {
            EvalKey<DCRTPoly> evalMultKey = key_switch;
            return evalMultKey;
        }

        EvalKey<DCRTPoly> receive_key_switch(EvalKey<DCRTPoly> key_switch) {
            EvalKey<DCRTPoly> evalMultKey = key_switch;
            return evalMultKey;
        }

        Ciphertext<DCRTPoly> receive_ct1(void) {
            Ciphertext<DCRTPoly> ct1;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext1.txt", ct1, SerType::BINARY) == false) {
                std::cerr << "Could not read the ciphertext" << std::endl;
            }
            return ct1;
        }
};

class FHEClient {
    public:
        CryptoContext<DCRTPoly> clientCC;
        KeyPair<DCRTPoly> keyPair;
        std::vector<double> data;
        PrivateKey<DCRTPoly> secretKey;

        EvalKey<DCRTPoly> evalMultKey;
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalSumKey;

        CryptoContext<DCRTPoly> receive_cc(void) {
            CryptoContext<DCRTPoly> cc;

            if(!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
            }

            clientCC = cc;
            return cc;
        }

        PublicKey<DCRTPoly> receive_server_publickey(void) {
            PublicKey<DCRTPoly> pk;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
                std::cerr << "Could not read public key" << std::endl;
            }
            return pk;
        }

        EvalKey<DCRTPoly> receive_key_switch(EvalKey<DCRTPoly> key_switch) {
            EvalKey<DCRTPoly> evalMultKey = key_switch;
            return evalMultKey;
        }

        EvalKey<DCRTPoly> send_joined_key_switch(CryptoContext<DCRTPoly> ccontext, EvalKey<DCRTPoly> priorkey, PublicKey<DCRTPoly> publickey) {
            CryptoContext<DCRTPoly> cc = ccontext;
            EvalKey<DCRTPoly> clientEvalMultKey = cc->MultiKeySwitchGen(secretKey, secretKey, priorkey);
            EvalKey<DCRTPoly> evalMultKey = cc->MultiAddEvalKeys(priorkey, clientEvalMultKey, publickey->GetKeyTag());
            return evalMultKey;
        }

        //Keep the secret, send the pk to the server
        void generate_client_key_pair(CryptoContext<DCRTPoly> ccontext, PublicKey<DCRTPoly> publickey) {
            CryptoContext<DCRTPoly> cc = ccontext;
            KeyPair<DCRTPoly> kp;
            kp = cc->MultipartyKeyGen(publickey);
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", kp.publicKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            }
            if (!Serial::SerializeToFile(DATAFOLDER + "/client1-key-private.txt", kp.secretKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
            }

            secretKey = kp.secretKey;
        }

        void send_encrypted_data(CryptoContext<DCRTPoly> ccontext, PublicKey<DCRTPoly> publickey) {
            CryptoContext<DCRTPoly> cc = ccontext;
            PublicKey<DCRTPoly> pk = publickey;
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext;

                std::cout << "\n Original Plaintext1: \n" << std::endl;
                std::cout << plaintext << std::endl;

            ciphertext = cc->Encrypt(pk, plaintext);
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext1.txt", ciphertext, SerType::BINARY)) {
                std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
            }
        }


};

int main(int argc, char* argv[]) {

    std::cout << "\n=================RUNNING FOR CKKS=====================" << std::endl;

    RunCKKS();

    return 0;
}


//Server
void RunCKKS() {
    uint batchSize = 16;
        // Initialize Public Key Containers

    FHEServer s;
    FHEClient c;
    s.generate_ccontext(3,50,16);
    s.send_ccontext();

    CryptoContext<DCRTPoly> cc = c.receive_cc();

    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Round 1 (party A)
    //Generate Server Keypair, sumkey, keyswitch
    kp1 = cc->KeyGen();
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
                 "into s_b*(s_a + s_b)..."
              << std::endl;
    auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party A) started." << std::endl;

    std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..." << std::endl;
    auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});

    std::cout << "Round 3 of key generation completed." << std::endl;

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
    c.data = read_data_1();
    s.send_server_public_key(kp2.publicKey);
    c.send_encrypted_data(c.receive_cc(), c.receive_server_publickey());


    std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    std::vector<double> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);
    Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(vectorOfInts3);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertext1;
    Ciphertext<DCRTPoly> ciphertext2;
    Ciphertext<DCRTPoly> ciphertext3;

    ciphertext1 = s.receive_ct1();
    ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
    ciphertext3 = cc->Encrypt(kp2.publicKey, plaintext3);

    ////////////////////////////////////////////////////////////
    // EvalAdd Operation on Re-Encrypted Data
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertextAdd12;
    Ciphertext<DCRTPoly> ciphertextAdd123;

    ciphertextAdd12  = cc->EvalAdd(ciphertext1, ciphertext2);
    ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

    auto ciphertextMultTemp = cc->EvalMult(ciphertext1, ciphertext3);
    auto ciphertextMult     = cc->ModReduce(ciphertextMultTemp);
    auto ciphertextEvalSum  = cc->EvalSum(ciphertext3, batchSize);

    ////////////////////////////////////////////////////////////
    // Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ////////////////////////////////////////////////////////////

    Plaintext plaintextAddNew1;
    Plaintext plaintextAddNew2;
    Plaintext plaintextAddNew3;

    DCRTPoly partialPlaintext1;
    DCRTPoly partialPlaintext2;
    DCRTPoly partialPlaintext3;

    Plaintext plaintextMultipartyNew;

    // distributed decryption

    auto ciphertextPartial1 = c.receive_cc()->MultipartyDecryptLead({ciphertextAdd123}, kp1.secretKey);

    auto ciphertextPartial2 = c.receive_cc()->MultipartyDecryptMain({ciphertextAdd123}, kp2.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    c.receive_cc()->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

    std::cout << "\n Original Plaintext: \n" << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;

    plaintextMultipartyNew->SetLength(plaintext2->GetLength());

    std::cout << "\n Resulting Fused Plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    Plaintext plaintextMultipartyMult;

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp2.secretKey);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
    partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

    cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

    plaintextMultipartyMult->SetLength(plaintext2->GetLength());

    std::cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts 1 "
                 "and 3: \n"
              << std::endl;
    std::cout << plaintextMultipartyMult << std::endl;

    std::cout << "\n";
}