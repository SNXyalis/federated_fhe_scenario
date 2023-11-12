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
CryptoContext<DCRTPoly> generate_crypto_context();
CryptoContext<DCRTPoly> read_crypto_context();
void update_clients();

class FHEClient {
    public:
        //Client
        CryptoContext<DCRTPoly> cc;
        std::vector<double> data;
        PublicKey<DCRTPoly> cpk; //Client public key
        PrivateKey<DCRTPoly> csk; //Client secret key
        EvalKey<DCRTPoly> ckk; //Client key switch
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> csumk; //Client + operation key
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> cmk; //Client * operation key

        //Server keys
        PublicKey<DCRTPoly> updatedServerPK;
        EvalKey<DCRTPoly> updatedServerKK; //keyswitch
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> updatedServerSumKey;
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> updatedServerMultKey;

        //Initialize new client
        FHEClient(CryptoContext<DCRTPoly> ccontext, PublicKey<DCRTPoly> serverPK, EvalKey<DCRTPoly> serverKeySwitch, std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> serverSum) {
            data = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};

            cc = ccontext;            
            KeyPair<DCRTPoly> kp = cc->MultipartyKeyGen(serverPK);
            
            if (!kp.good()) {
                std::cout << "Key generation failed!" << std::endl;
                exit(1);
            }

            cpk = kp.publicKey;
            csk = kp.secretKey;
            ckk = cc->MultiKeySwitchGen(csk, csk, serverKeySwitch);
            csumk = cc->MultiEvalSumKeyGen(csk, serverSum, cpk->GetKeyTag());

            //Update server keys
            updatedServerPK = cpk;
            updatedServerKK = cc->MultiAddEvalKeys(serverKeySwitch, ckk, updatedServerPK->GetKeyTag());
            updatedServerSumKey = cc->MultiAddEvalSumKeys(serverSum, csumk, updatedServerPK->GetKeyTag());
        }

        
        void update_server_keyswitch_key(EvalKey<DCRTPoly> ukeyswitchkey) {
            updatedServerKK = ukeyswitchkey;
        }

        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> update_server_multi_key(std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> old_server_multi_key) {
            cmk = cc->MultiMultEvalKey(csk, updatedServerKK, updatedServerPK->GetKeyTag());
            updatedServerMultKey = cc->MultiAddEvalMultKeys(old_server_multi_key, cmk, updatedServerKK->GetKeyTag());
            return updatedServerMultKey;
        }

        void update_server_public_key(PublicKey<DCRTPoly> upk) {
            updatedServerPK = upk;
        }

        void update_server_sum_key(std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> usumkey) {
            updatedServerSumKey = usumkey;
        }

        //Encrypts Weights and sends them to server - Algorithm 1
        Ciphertext<DCRTPoly> encrypt(PublicKey<DCRTPoly> upk, std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>  sumkey, EvalKey<DCRTPoly>  keyswitch, std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> multikey) {
            update_server_public_key(upk);
            update_server_sum_key(sumkey);
            update_server_keyswitch_key(keyswitch);
            update_server_multi_key(multikey);

            cc->InsertEvalSumKey(updatedServerSumKey);
            cc->InsertEvalMultKey({updatedServerMultKey});

            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(data);
            Ciphertext<DCRTPoly> ciphertext1;
            ciphertext1 = cc->Encrypt(updatedServerPK, plaintext);

            return ciphertext1;
        }
};

std::vector<FHEClient> fhe_clients;

//Mock Weights for client 1
std::vector<double> read_data_1(void) {
    std::vector<double> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
    return vectorOfInts1
}

//Mock Weights for client 2
std::vector<double> read_data_2(void) {
    std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    return vectorOfInts2
}

//Mock Weights for client 3
std::vector<double> read_data_3(void) {
    std::vector<double> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};
    return vectorOfInts3
}




int main(int argc, char* argv[]) {

    std::cout << "\n=================RUNNING FOR CKKS=====================" << std::endl;

    RunCKKS();

    return 0;
}

CryptoContext<DCRTPoly> generate_crypto_context() {
    usint batchSize = 16;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    if(!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
    }

    return cc;
}

CryptoContext<DCRTPoly> read_crypto_context() {
    CryptoContext<DCRTPoly> cc;
    if(!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
    }

    return cc;
}


//Server
void RunCKKS() {
    
    //CryptoContext<DCRTPoly> cc = generate_crypto_context();
    CryptoContext<DCRTPoly> cc = read_crypto_context();

    // Initialize Key Containers
    KeyPair<DCRTPoly> kp1;

    // Round 1 (party A)
    kp1 = cc->KeyGen();

    if (!kp1.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    // Server key switch
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Server sum key
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    //New clients connect to the server
    FHEClient client1(cc, kp1.publicKey, evalMultKey, evalSumKeys);

    // auto updatedServerPK = client1.updatedServerPK;
    // auto updatedServerKK = client1.updatedServerKK;
    // auto updatedServerSumKey = client1.updatedServerSumKey;


    // // Mult keys should be processed after the creation of the clients because we require last keyswitch
    // // Server mult key 
    // auto evalMultServer = cc->MultiMultEvalKey(kp1.secretKey, updatedServerPK, client1.updatedServerPK->GetKeyTag());
    
    // //Joined multiplication key
    // auto evalMultServerJoined = FHEClient.update_server_multi_key(evalMultServer);

    // cc->InsertEvalSumKey(updatedServerSumKey);
    // cc->InsertEvalMultKey({evalMultServerJoined});

    // std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    // Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

    // Ciphertext<DCRTPoly> ciphertext1;
    // Ciphertext<DCRTPoly> ciphertext2;

    // ciphertext1 = FHEClient.encrypt(updatedServerPK, updatedServerSumKey, updatedServerKK, evalMultServerJoined);
    // ciphertext2 = cc->Encrypt(updatedServerPK, plaintext2);

    // Ciphertext<DCRTPoly> Waggr;
    // Waggr  = cc->EvalAdd(ciphertext1, ciphertext2);

    // Plaintext plaintextAddNew1;
    // Plaintext plaintextAddNew2;

    // DCRTPoly partialPlaintext1;
    // DCRTPoly partialPlaintext2;

    // Plaintext plaintextMultipartyNew;
    // const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    // const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();

    // Plaintext results;

    // auto ciphertextPartial1 = cc->MultipartyDecryptLead({Waggr}, kp1.secretKey); //Leader

    // auto ciphertextPartial2 = cc->MultipartyDecryptMain({Waggr}, kp2.secretKey);

    // //Push the partial Ciphertexts into an array
    // std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult; //Stores the result
    // partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
    // partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

    // //Combine the partial ciphertexts of the array into the result ciphertext
    // cc->MultipartyDecryptFusion(partialCiphertextVecMult, &results);

    // results->SetLength(plaintext1->GetLength());

    // //Print result
    // std::cout << "\n Resulting Fused Plaintext of the average of the weights " << std::endl;
    // std::cout << results << std::endl;

    std::cout << "\n";


}