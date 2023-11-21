#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "ciphertext-ser.h"
#include <vector>

using namespace lbcrypto;

usint active_clients = 0;

const std::string DATAFOLDER = "demoData";

void scenario(int num_clients);
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

//generate array
std::vector<double> generate_data(void) {
    std::vector<double> data_vector;
    for(int i = 0; i < 12; i++) {
        data_vector.push_back( ((double)(rand() % 100)) / 100.0);
    }
    return data_vector;
}

class Aggregator {
    public:
        CryptoContext<DCRTPoly> m_serverCC;
        double numClient = 0;
        std::vector<EvalKey<DCRTPoly>> keyswitch_keys;
        std::vector<EvalKey<DCRTPoly>> mult_keys;
        std::vector<Ciphertext<DCRTPoly>> ciphertexts;

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

        Ciphertext<DCRTPoly> receive_partial_decrypted_ct() {
            Ciphertext<DCRTPoly> partial_result;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/partial-ct-1.txt", partial_result, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
            return partial_result;
        }

        void send_ct(Ciphertext<DCRTPoly> ct) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "/partial-ct-1.txt", ct, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
        }

        void send_lead_ct(std::vector<Ciphertext<DCRTPoly>> ct) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "/lead-ct-1.txt", ct, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
        }

        void send_result_ct(Ciphertext<DCRTPoly> result) {
            if (Serial::SerializeToFile(DATAFOLDER + "/result-ct.txt", result, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
        }

        std::vector<double> make_vector(int vectorsize) {
            std::vector<double> server_vector;
            for (int i = 1; i <= vectorsize; i++) {
                server_vector.push_back(1.0/numClient);
            }
            return server_vector;
        }

        void perform_calculations() {
            numClient = 3.0;//(double) ciphertexts.size();
            std::vector<double> vectorOfClients = make_vector(12);
            Plaintext plaintext_clients = m_serverCC->MakeCKKSPackedPlaintext(vectorOfClients);
            Ciphertext<DCRTPoly> Waggr = ciphertexts[0];
            for(auto& it : ciphertexts) {
                Waggr  = m_serverCC->EvalAdd(Waggr, it);

            }

            auto ciphertextMultTemp = m_serverCC->EvalMult(Waggr, plaintext_clients);
            auto ciphertextMult     = m_serverCC->ModReduce(ciphertextMultTemp);

            send_result_ct(ciphertextMult);
        }
};

class FHEClient {
    public:

        CryptoContext<DCRTPoly> clientCC;

        //Client-generated keys
        KeyPair<DCRTPoly> kp;
        PrivateKey<DCRTPoly> secretKey;
        PublicKey<DCRTPoly> publicKey;

        //Shared keys
        PublicKey<DCRTPoly> server_pk;

        //Storage
        std::vector<double> data;
        size_t vector_len; 
        std::vector<Ciphertext<DCRTPoly>> partial_vector;
        Ciphertext<DCRTPoly> result;
        double numClient = 0;

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

        void send_server_public_key(PublicKey<DCRTPoly> pk) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            }
        }

        void receive_server_publickey(void) {
            PublicKey<DCRTPoly> pk;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
                std::cerr << "Could not read public key" << std::endl;
            }
            server_pk =pk;
        }

        PublicKey<DCRTPoly> receive_public_key(void) {
            PublicKey<DCRTPoly> pk;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
                std::cerr << "Could not read public key" << std::endl;
            }
            return pk;
        }

        void send_key_switch(EvalKey<DCRTPoly> key_switch) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-switch.txt", key_switch, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
            EvalKey<DCRTPoly> evalMultKey = key_switch;
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

        void send_joined_key_switch(EvalKey<DCRTPoly> priorkey) {
            EvalKey<DCRTPoly> clientEvalMultKey = clientCC->MultiKeySwitchGen(secretKey, secretKey, priorkey);
            EvalKey<DCRTPoly> evalMultKey = clientCC->MultiAddEvalKeys(priorkey, clientEvalMultKey, publicKey->GetKeyTag());
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-switch.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-public.txt" << std::endl;
            }
        }

        void send_evalSumKey(void) {
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
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> receive_evalSumKey() {
            std::ifstream emkeys(DATAFOLDER + "/key-eval-sum.txt", std::ios::in | std::ios::binary);
            if (!emkeys.is_open()) {
                std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-sum.txt" << std::endl;
            }
            if (clientCC->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
                std::cerr << "Could not deserialize the eval mult key file" << std::endl;
            }

            std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalSumKeys =
                std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(clientCC->GetEvalSumKeyMap(server_pk->GetKeyTag()));
            return evalSumKeys;
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> send_joined_evalSumKey(std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> priorkey) {
            auto evalSumKeys = clientCC->MultiEvalSumKeyGen(secretKey, priorkey, publicKey->GetKeyTag());
            auto evalSumKeysJoin = clientCC->MultiAddEvalSumKeys(priorkey, evalSumKeys, publicKey->GetKeyTag());
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

        void send_evalMultKey(EvalKey<DCRTPoly> evalMultKey) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-eval-mult.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
        }

        EvalKey<DCRTPoly> receive_evalMultKey() {
            EvalKey<DCRTPoly> evalMultKey;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-eval-mult.txt", evalMultKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
            return evalMultKey;
        }

        void send_joined_evalMultKey(EvalKey<DCRTPoly> priorkey, EvalKey<DCRTPoly> keyswitch) {
            EvalKey<DCRTPoly> client_key = clientCC->MultiMultEvalKey(secretKey, keyswitch, server_pk->GetKeyTag());
            EvalKey<DCRTPoly> evalMultFinal = clientCC->MultiAddEvalMultKeys(priorkey, client_key, keyswitch->GetKeyTag());
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-eval-mult.txt", evalMultFinal, SerType::BINARY)) {
                std::cerr << "Error writing serialization of keyswitch key to key-eval-mult.txt" << std::endl;
            }
        }

        //Keep the secret, send the pk to the server
        void generate_client_key_pair() {
            kp = clientCC->MultipartyKeyGen(server_pk);
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", kp.publicKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            }
            if (!Serial::SerializeToFile(DATAFOLDER + "/client1-key-private.txt", kp.secretKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
            }

            secretKey = kp.secretKey;
            publicKey = kp.publicKey;
        }

        void send_encrypted_data() {
            Plaintext plaintext = clientCC->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext;

            std::cout << "W: " << plaintext << std::endl;
            vector_len = plaintext->GetLength();

            ciphertext = clientCC->Encrypt(server_pk, plaintext);
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertext1.txt", ciphertext, SerType::BINARY)) {
                std::cerr << "Error writing serialization of ciphertext 1 to ciphertext1.txt" << std::endl;
            }
        }

        void receive_partial_ct() {
            std::vector<Ciphertext<DCRTPoly>> partial_ct;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/partial-ct-1.txt", partial_ct, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
            partial_vector.push_back(partial_ct[0]);
        }

        void receive_ct_result() {
            if (Serial::DeserializeFromFile(DATAFOLDER + "/result-ct.txt", result, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
        }

        void receive_lead_ct() {
            std::vector<Ciphertext<DCRTPoly>> tmp;
            if (!Serial::DeserializeFromFile(DATAFOLDER + "/" + "/lead-ct-1.txt", tmp, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
            partial_vector.push_back(tmp[0]);
        }

        void send_partial_decrypted_ct() {
            auto partial_dec = clientCC->MultipartyDecryptMain({result}, secretKey);
            partial_vector.push_back(partial_dec[0]);
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "/partial-ct-1.txt", partial_dec, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
        }

        void decrypt_result() {
            Plaintext plaintextMultipartyNew;
            clientCC->MultipartyDecryptFusion(partial_vector, &plaintextMultipartyNew);
            plaintextMultipartyNew->SetLength(vector_len);

            std::cout << "\n Resulting Plaintext: \n" << std::endl;
            std::cout << plaintextMultipartyNew << std::endl;

            std::cout << "\n";
        }

        Ciphertext<DCRTPoly> receive_ct1(void) {
            Ciphertext<DCRTPoly> ct1;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext1.txt", ct1, SerType::BINARY) == false) {
                std::cerr << "Could not read the ciphertext" << std::endl;
            }
            return ct1;
        }

        std::vector<double> make_vector(int vectorsize) {
            std::vector<double> server_vector;
            for (int i = 1; i <= vectorsize; i++) {
                server_vector.push_back(1.0/numClient);
            }
            return server_vector;
        }

        void send_result_ct(Ciphertext<DCRTPoly> result) {
            if (Serial::SerializeToFile(DATAFOLDER + "/result-ct.txt", result, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
        }

        Ciphertext<DCRTPoly> receive_partial_decrypted_ct() {
            Ciphertext<DCRTPoly> partial_result;
            if (Serial::DeserializeFromFile(DATAFOLDER + "/partial-ct-1.txt", partial_result, SerType::BINARY) == false) {
                std::cerr << "Could not read the partial ciphertext" << std::endl;
            }
            return partial_result;
        }

        void send_ct(Ciphertext<DCRTPoly> ct) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "/partial-ct-1.txt", ct, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
        }

        void send_lead_ct() {
            auto ciphertextPartial1 = clientCC->MultipartyDecryptLead({result}, secretKey);
            partial_vector.push_back(ciphertextPartial1[0]);
            if (!Serial::SerializeToFile(DATAFOLDER + "/" + "/lead-ct-1.txt", ciphertextPartial1, SerType::BINARY)) {
                std::cerr << "Error writing serialization of partial ct1 to partial-ct-1.txt" << std::endl;
            }
        }

        void generate_ccontext(int multDepth, int scaleFactorBits, int batchSize) {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(multDepth);
            parameters.SetScalingModSize(scaleFactorBits);
            parameters.SetBatchSize(batchSize);

            clientCC = GenCryptoContext(parameters);

            clientCC->Enable(PKE);
            clientCC->Enable(KEYSWITCH);
            clientCC->Enable(LEVELEDSHE);
            clientCC->Enable(ADVANCEDSHE);
            clientCC->Enable(MULTIPARTY);

            // Output the generated parameters
            std::cout << "p = " << clientCC->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
            std::cout << "n = " << clientCC->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
            std::cout << "log2 q = " << log2(clientCC->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
                    << std::endl;
        }
};

int main(int argc, char* argv[]) {

    std::cout << "\n=================RUNNING FOR CKKS=====================" << std::endl;

    scenario(3);

    return 0;
}

FHEClient new_client() {
    FHEClient c;
    c.receive_cc();
    c.receive_server_publickey();

    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> server_evalSumKey = c.receive_evalSumKey(); // Should get sum map before new keypair
    
    //keypair
    c.generate_client_key_pair(); // public key is send to server/next client with this

    //keyswitch
    c.send_joined_key_switch(c.receive_key_switch());

    //sum 
    c.send_joined_evalSumKey(server_evalSumKey);
    c.send_ccontext();

    return c;
}

FHEClient new_lead_client() {
    FHEClient s; //Lead client

    // Server //
    s.receive_cc();

    //Generate Server Keypair, sumkey, keyswitch
    s.kp = s.clientCC->KeyGen();
    s.secretKey = s.kp.secretKey;
    s.publicKey = s.kp.publicKey;
    auto evalMultKey = s.clientCC->KeySwitchGen(s.secretKey, s.secretKey);
    s.clientCC->EvalSumKeyGen(s.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(s.clientCC->GetEvalSumKeyMap(s.publicKey->GetKeyTag()));


    s.send_ccontext();
    s.send_server_public_key(s.publicKey); 
    s.send_key_switch(evalMultKey);
    s.send_evalSumKey();

    return s;
}

void send_encrypted_data_process(FHEClient &c) {
    c.data = generate_data();;
    c.receive_server_publickey();
    c.send_encrypted_data();
}

void client_add_multiplication_key(FHEClient &c) {
    c.receive_server_publickey();
    c.send_joined_evalMultKey(c.receive_evalMultKey(), c.receive_key_switch());
}

void lead_client_add_multiplication_key(FHEClient &s) {
    s.receive_cc(); //updated context + updated sum
    s.receive_public_key(); //updated pk
    EvalKey<DCRTPoly> server_keyswitch = s.receive_key_switch();// updated keyswitch
    EvalKey<DCRTPoly> server_mult_key = s.clientCC->MultiMultEvalKey(s.secretKey, server_keyswitch, s.publicKey->GetKeyTag()); //start multiplication key generation
    s.send_key_switch(server_keyswitch);
    s.send_evalMultKey(server_mult_key);
}
//Key Generation process
std::vector<FHEClient> init_clients(int num_of_clients) {

    FHEClient s = new_lead_client();
    std::vector<FHEClient> v;
    for ( int i = 0; i < num_of_clients; i++) {
        v.push_back(new_client());
    }
    
    lead_client_add_multiplication_key(s);

    for ( int i = 0; i < num_of_clients; i++) {
        client_add_multiplication_key(v[i]);
    }

    s.receive_evalMultKey();// updated multiplication
    v.push_back(s);
    return v;
}

void decrypt_process(std::vector<FHEClient> &clients) {

    for(auto& it : clients) {
        it.receive_ct_result();
    }

    for(auto& elem_i : clients) {
        if(&elem_i == &clients.back()) {
            elem_i.send_lead_ct();
        }else {
            elem_i.send_partial_decrypted_ct();
        }

        for(auto& elem_j : clients) {
            if(&elem_i == &elem_j) {
                continue;
            }else {
                if(&elem_i == &clients.back()) {
                    elem_j.receive_lead_ct();
                }else {
                    elem_j.receive_partial_ct();
                }
            }
        }
    }

    for(auto& it : clients) {
        it.decrypt_result();
    }
}

//Server
void scenario(int num_clients) {
    Aggregator a;
    a.generate_ccontext(3,50,16);
    a.send_ccontext();

    CryptoContext<DCRTPoly> cc;
    std::vector<FHEClient> clients = init_clients(3);
    // FHEClient s = clients[2];
    // FHEClient c = clients[0];
    // FHEClient c1 = clients[1];
    // cc = s.clientCC;


    // Encryption process
    a.receive_cc();

    for(auto& it : clients) {
        send_encrypted_data_process(it);
        a.ciphertexts.push_back(a.receive_ct1());
    }

    // //Client
    // send_encrypted_data_process(c);

    // //Server
    // a.ciphertexts.push_back(a.receive_ct1());

    // //Client 1
    // send_encrypted_data_process(c1);

    // //Server
    // a.ciphertexts.push_back(a.receive_ct1());

    a.perform_calculations(); // kanei lathos epeidh kanei add to prwto ciphertext 2 fores

    decrypt_process(clients);
    // //Lead Client 
    // s.receive_ct_result();
    // s.send_lead_ct();

    // //Client
    // c.receive_ct_result();
    
    // //CLient 1
    // c1.receive_ct_result();
    // c1.receive_lead_ct();
    // // for client in clients.. send partial dec
    // c1.send_partial_decrypted_ct();

    
    // //Client
    // c.receive_partial_ct();
    // c.receive_lead_ct();
    // c.send_partial_decrypted_ct(); //all partials are now inside c so we can decrypt
    // c.decrypt_result();


    // //Client1
    // c1.receive_partial_ct();
    // c1.decrypt_result();

}