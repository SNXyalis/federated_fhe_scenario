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

        void receive_cc(void) {
            if(!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", m_serverCC, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
            }
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

        void send_key_switch(EvalKey<DCRTPoly> key_switch) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-switch.txt", key_switch, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
            EvalKey<DCRTPoly> evalMultKey = key_switch;
        }

        PublicKey<DCRTPoly> receive_public_key(void) {
            PublicKey<DCRTPoly> pk;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
                std::cerr << "Could not read public key" << std::endl;
            }
            return pk;
        }

        EvalKey<DCRTPoly> receive_key_switch() {
            EvalKey<DCRTPoly> evalMultKey;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-switch.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
            return evalMultKey;
        }

        void send_evalSumKey(void) {
            std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-sum.txt", std::ios::out | std::ios::binary);
            if (emkeyfile.is_open()) {
                if (m_serverCC->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
                    std::cerr << "Error writing serialization of the eval mult keys to "
                                "key-eval-sum.txt"
                            << std::endl;
                }
                emkeyfile.close();
            }
            else {
                std::cerr << "Error serializing eval sum keys" << std::endl;
            }
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> receive_evalSumKey(PublicKey<DCRTPoly> publickey) {
            std::ifstream emkeys(DATAFOLDER + "/key-eval-sum.txt", std::ios::in | std::ios::binary);
            if (!emkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-sum.txt" << std::endl;
            }
            if (m_serverCC->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
                std::cerr << "Could not deserialize the eval mult key file" << std::endl;
            }

            std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalSumKeys =
                std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(m_serverCC->GetEvalSumKeyMap(publickey->GetKeyTag()));
            //m_serverCC.InsertEvalSumKey(evalSumKeys);
            std::cerr << "test 6" << std::endl;

            return evalSumKeys;
        }

        void send_evalMultKey(EvalKey<DCRTPoly> evalMultKey) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-eval-mult.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
        }

        void receive_evalMultKey() {
            EvalKey<DCRTPoly> test;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-eval-mult.txt", test, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }

            m_serverCC->InsertEvalMultKey({test});
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

        //Client-generated keys
        std::vector<double> data;
        KeyPair<DCRTPoly> kp;
        PrivateKey<DCRTPoly> secretKey;
        PublicKey<DCRTPoly> publicKey;
        EvalKey<DCRTPoly> keySwitchKey;
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> cevalSumKey;
        EvalKey<DCRTPoly> cevalMultKey;

        //Shared keys

        EvalKey<DCRTPoly> evalMultKey;
        EvalKey<DCRTPoly> joinedKeySwitchKey;
        PublicKey<DCRTPoly> joinedpublicKey;

        void receive_cc(void) {
            CryptoContext<DCRTPoly> cc;

            if(!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
            }

            clientCC = cc;
        }

        void send_ccontext(void) {
            if(!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", clientCC, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
            }
        }

        PublicKey<DCRTPoly> receive_server_publickey(void) {
            PublicKey<DCRTPoly> pk;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
                std::cerr << "Could not read public key" << std::endl;
            }
            return pk;
        }

        EvalKey<DCRTPoly> receive_key_switch() {
            EvalKey<DCRTPoly> evalMultKey;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-switch.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
            return evalMultKey;
            //EvalKey<DCRTPoly> evalMultKey = key_switch;
            //return evalMultKey;
        }

        void send_joined_key_switch(CryptoContext<DCRTPoly> ccontext, EvalKey<DCRTPoly> priorkey, PublicKey<DCRTPoly> publickey) {
            EvalKey<DCRTPoly> clientEvalMultKey = clientCC->MultiKeySwitchGen(secretKey, secretKey, priorkey);
            keySwitchKey = clientEvalMultKey;
            EvalKey<DCRTPoly> evalMultKey = clientCC->MultiAddEvalKeys(priorkey, clientEvalMultKey, publickey->GetKeyTag());
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-switch.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> receive_evalSumKey(PublicKey<DCRTPoly> publickey) {
            std::ifstream emkeys(DATAFOLDER + "/key-eval-sum.txt", std::ios::in | std::ios::binary);
            if (!emkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-sum.txt" << std::endl;
            }
            if (clientCC->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
                std::cerr << "Could not deserialize the eval mult key file" << std::endl;
            }

            std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalSumKeys =
                std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(clientCC->GetEvalSumKeyMap(publickey->GetKeyTag()));
            return evalSumKeys;
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> send_joined_evalSumKey(CryptoContext<DCRTPoly> ccontext, std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> priorkey, PublicKey<DCRTPoly> publickey) {
            PublicKey<DCRTPoly> pk = publickey;
            auto evalSumKeys = clientCC->MultiEvalSumKeyGen(secretKey, priorkey, pk->GetKeyTag());
            cevalSumKey = evalSumKeys;
            auto evalSumKeysJoin = clientCC->MultiAddEvalSumKeys(priorkey, evalSumKeys, pk->GetKeyTag());
            clientCC->InsertEvalSumKey(evalSumKeysJoin);

            std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-sum.txt", std::ios::out | std::ios::binary);
            if (emkeyfile.is_open()) {
                if (clientCC->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
                    std::cerr << "Error writing serialization of the eval mult keys to "
                                "key-eval-sum.txt"
                            << std::endl;
                }
                emkeyfile.close();
            }
            else {
                std::cerr << "Error serializing eval sum keys" << std::endl;
            }
            return evalSumKeysJoin;
        }

        EvalKey<DCRTPoly> receive_evalMultKey() {
            EvalKey<DCRTPoly> evalMultKey;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-eval-mult.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
            return evalMultKey;
        }

        void send_joined_evalMultKey(EvalKey<DCRTPoly> priorkey, EvalKey<DCRTPoly> keyswitch, PublicKey<DCRTPoly> publicKey) {
            EvalKey<DCRTPoly> client_key = clientCC->MultiMultEvalKey(secretKey, keyswitch, publicKey->GetKeyTag());
            EvalKey<DCRTPoly> evalMultFinal = clientCC->MultiAddEvalMultKeys(priorkey, client_key, keyswitch->GetKeyTag());
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-eval-mult.txt", evalMultFinal, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
        }

        //Keep the secret, send the pk to the server
        void generate_client_key_pair(CryptoContext<DCRTPoly> ccontext, PublicKey<DCRTPoly> publickey) {
            CryptoContext<DCRTPoly> cc = ccontext;
            kp = clientCC->MultipartyKeyGen(publickey);
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", kp.publicKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            }
            if (!Serial::SerializeToFile(DATAFOLDER + "/client1-key-private.txt", kp.secretKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
            }

            secretKey = kp.secretKey;
            publicKey = kp.publicKey;
        }

        void send_encrypted_data(PublicKey<DCRTPoly> publickey) {
            PublicKey<DCRTPoly> pk = publickey;
            Plaintext plaintext = clientCC->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext;

                std::cout << "\n Original Plaintext1: \n" << std::endl;
                std::cout << plaintext << std::endl;

            ciphertext = clientCC->Encrypt(pk, plaintext);
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

    // Server //
    s.generate_ccontext(3,50,16);
    CryptoContext<DCRTPoly> cc = s.m_serverCC;
    KeyPair<DCRTPoly> kp1;

    //Generate Server Keypair, sumkey, keyswitch
    kp1 = cc->KeyGen();
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.publicKey->GetKeyTag()));


    s.send_ccontext();
    s.send_server_public_key(kp1.publicKey); // Server sends public key
    s.send_key_switch(evalMultKey);
    s.send_evalSumKey();
    //TODO possibly will need updated context as well

    // Client //
    FHEClient c;
    c.receive_cc();

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> server_evalSumKey = c.receive_evalSumKey(c.receive_server_publickey()); // Should get sum map before new keypair
    
    //keypair
    c.generate_client_key_pair(c.clientCC, c.receive_server_publickey());
    PublicKey<DCRTPoly> client_pk = c.publicKey;
    PrivateKey<DCRTPoly> client_sk = c.secretKey;
    
    //keyswitch
    c.send_joined_key_switch(c.clientCC, c.receive_key_switch(), client_pk);

    //sum 
    c.send_joined_evalSumKey(c.clientCC, server_evalSumKey, client_pk);
    c.send_ccontext();

    // Server //
    s.receive_cc();
    cc = s.m_serverCC;
    PublicKey<DCRTPoly> server_pk = s.receive_public_key();

    //keyswitch
    EvalKey<DCRTPoly> server_keyswitch = s.receive_key_switch();// Server will be able to access this

    //multi
    EvalKey<DCRTPoly> server_mult_key = cc->MultiMultEvalKey(kp1.secretKey, server_keyswitch, server_pk->GetKeyTag());
    s.send_key_switch(server_keyswitch);
    s.send_evalMultKey(server_mult_key);

    // // Client // 
    PublicKey<DCRTPoly> updated_server_pk = c.receive_server_publickey();
    EvalKey<DCRTPoly> serv_mult_key = c.receive_evalMultKey();
    EvalKey<DCRTPoly> joined_keyswitch = c.receive_key_switch();

    c.send_joined_evalMultKey(c.receive_evalMultKey(), c.receive_key_switch(), c.receive_server_publickey());
    // EvalKey<DCRTPoly> client_key = c.clientCC->MultiMultEvalKey(c.secretKey, joined_keyswitch, updated_server_pk->GetKeyTag());
    // EvalKey<DCRTPoly> evalMultFinal = c.clientCC->MultiAddEvalMultKeys(serv_mult_key, client_key, joined_keyswitch->GetKeyTag());
    // if (!Serial::SerializeToFile(DATAFOLDER + "/key-eval-mult.txt", evalMultFinal, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
    // }

    // Server//
    s.receive_evalMultKey();
    // EvalKey<DCRTPoly> test;
    // if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-eval-mult.txt", test, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
    // }

    // cc->InsertEvalMultKey({test});
    cc = s.m_serverCC;


    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
    c.data = read_data_1();
    s.send_server_public_key(server_pk);
    c.send_encrypted_data(c.receive_server_publickey());


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
    ciphertext2 = cc->Encrypt(server_pk, plaintext2);
    ciphertext3 = cc->Encrypt(server_pk, plaintext3);

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

    auto ciphertextPartial1 = c.clientCC->MultipartyDecryptLead({ciphertextAdd123}, kp1.secretKey);

    auto ciphertextPartial2 = c.clientCC->MultipartyDecryptMain({ciphertextAdd123}, client_sk);

    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    c.clientCC->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

    std::cout << "\n Original Plaintext: \n" << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;

    plaintextMultipartyNew->SetLength(plaintext2->GetLength());

    std::cout << "\n Resulting Fused Plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    Plaintext plaintextMultipartyMult;

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, client_sk);

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