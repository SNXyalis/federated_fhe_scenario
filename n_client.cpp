#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"
#include "ciphertext-ser.h"
#include <vector>


using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

class FHEClient {
    public:
        PublicKey<DCRTPoly> cpk; //Client public key
        PrivateKey<DCRTPoly> csk; //Client secret key
        EvalKey<DCRTPoly> ckk; //Client key switch
        EvalKey<DCRTPoly> csumk; //Client + operation key
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> cmk; //Client * operation key
};

void RunCKKS();
CryptoContext<DCRTPoly> generate_crypto_context();
CryptoContext<DCRTPoly> read_crypto_context();

int main(int argc, char* argv[]) {

    std::vector<FHEClient> g1;

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



void RunCKKS() {
    
    //CryptoContext<DCRTPoly> cc = generate_crypto_context();
    CryptoContext<DCRTPoly> cc = read_crypto_context();

    // Initialize Key Containers
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;
    KeyPair<DCRTPoly> kp3; 

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->KeyGen();

    if (!kp1.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    // Generate evalmult key part for A // Paragei eval key  gia ton server apo to secret key pou tha xrhsimopoithei gia thn joined praksh key switch
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum map part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    //Generate key pair for party B
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);

    if (!kp2.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    //Generate mult key for party B // Paragei eval key gia to 2o party apo to secret key pou tha xrhsimopoithei gia thn praksh key switch
    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

    //Combine mult key of party A and party B //Kanei Join 2 eval keys gia thn key switch praksh
    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    //This is used if we need 2 it to work with 2 parties instead of 3
    //Generate partial mult key for party B
    // std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
    //              "into s_b*(s_a + s_b)..."
    //           << std::endl;
    // auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());

    //Generate sum key of party B // Paragei eval key gia to 2o party apo to secret key pou tha xrhsimopoish gia thn praksh prostheshs
    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

    //Combine sum key of party A and party B // Knaei Join 2 eval key gia thn prosthesh
    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    //Generate key pair for party C
    std::cout << "Joint public key for (s_a + s_b + s_c) is generated..." << std::endl;
    kp3 = cc->MultipartyKeyGen(kp2.publicKey);

    if (!kp3.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party C) started." << std::endl;

    //Generate key pair for party C // Paragei eval key gia to 3o party apo to secret key pou tha xrhsimopoithei gia thn praksh key switch
    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey2);

    //Combile mult key of party A, party B, party C //Kanei Join 2 eval keys gia thn key switch praksh
    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());

    //Generate partial mult key using 3-party mult key for party C // Paragei eval  gia ot 3o party key gia multiplication
    auto evalMultCABC = cc->MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());

    //Generate sum key for party C // Paragei eval key gia to 3o party apo to secret key pou tha xrhsimopoish gia thn praksh prostheshs
    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysB, kp3.publicKey->GetKeyTag());

    //Combine sum key of party A, party B, party C // Knaei Join 2 eval key gia thn prosthesh
    auto evalSumKeysJoin2 = cc->MultiAddEvalSumKeys(evalSumKeysJoin, evalSumKeysC, kp3.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin2);

    std::cout << "Round 3 of key generation completed." << std::endl;

    std::cout << "Round 4 (party A) started." << std::endl;

    // Paragei eval  gia ot 1o party key gia multiplication
    std::cout << "Joint key (s_a + s_b + s_c) is transformed into s_a*(s_a + s_b + s_c)..." << std::endl;
    auto evalMultAABC = cc->MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;

    // Kanei Join 2 eval keys gia multiplication
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultCABC, evalMultABC->GetKeyTag());

    std::cout << "Round 4 of completed." << std::endl;
    
     // Paragei eval  gia ot 2o party key gia multiplication
    std::cout << "Round 5 of (party B) started." << std::endl;
    std::cout << "Joint key (s_a + s_b + s_c) is transformed into s_b*(s_a + s_b + s_c)..." << std::endl;
    auto evalMultBABC = cc->MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
        std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b + s_c)*(s_a + s_b + s_c)..."
              << std::endl;

    // Kanei Join 2 eval keys gia multiplication
    auto evalMultFinal2 = cc->MultiAddEvalMultKeys(evalMultFinal, evalMultBABC, evalMultABC->GetKeyTag());
    //auto evalMultFinal2 = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultCABC, evalMultABC->GetKeyTag());

    //auto evalMultFinal3 = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultABC->GetKeyTag());

    //cc->InsertEvalMultKey({evalMultFinal});
    cc->InsertEvalMultKey({evalMultFinal2});

    //cc->InsertEvalMultKey({evalMultFinal3});

    std::cout << "Round 5 of key generation completed." << std::endl;
    
    std::cout << "Weights:" << std::endl;

    std::vector<double> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
    std::vector<double> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    std::vector<double> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);
    Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(vectorOfInts3);

    std::cout << "W0: " << plaintext1 << std::endl;
    std::cout << "W1: " << plaintext2 << std::endl;
    std::cout << "W2: " << plaintext3 << std::endl;

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> ciphertext1;
    Ciphertext<DCRTPoly> ciphertext2;
    Ciphertext<DCRTPoly> ciphertext3;

    ciphertext1 = cc->Encrypt(kp3.publicKey, plaintext1);
    ciphertext2 = cc->Encrypt(kp3.publicKey, plaintext2);
    ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

    ////////////////////////////////////////////////////////////
    // EvalAdd Operation on Re-Encrypted Data
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> Waggr;

    //Add Weights to Waggr
    Waggr  = cc->EvalAdd(ciphertext1, ciphertext2);
    Waggr = cc->EvalAdd(Waggr, ciphertext3);

    // Multiply Waggr by N in power of -1, where N is the number of clients
    std::vector<double> vectorOfClients = {0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333, 0.333333}; // 3 clients -> 1/3 
    Plaintext plaintext_clients = cc->MakeCKKSPackedPlaintext(vectorOfClients);

    auto ciphertextMultTemp = cc->EvalMult(Waggr, plaintext_clients);
    auto ciphertextMult     = cc->ModReduce(ciphertextMultTemp);
    //auto ciphertextEvalSum  = cc->EvalSum(ciphertext3, batchSize);

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

    const std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams = kp1.secretKey->GetCryptoParameters();
    const std::shared_ptr<typename DCRTPoly::Params> elementParams     = cryptoParams->GetElementParams();


    //Partially decrypt from each client a part of the final result
    Plaintext plaintextMultipartyMult;

    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1.secretKey); //Leader

    auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp2.secretKey);

    auto ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextMult}, kp3.secretKey);

    //Push the partial Ciphertexts into an array
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult; //Stores the result
    partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial3[0]);

    //Combine the partial ciphertexts of the array into the result ciphertext
    cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

    plaintextMultipartyMult->SetLength(plaintext1->GetLength());

    //Print result
    std::cout << "\n Resulting Fused Plaintext of the average of the weights "
                 "(3 clients): \n"
              << std::endl;
    std::cout << plaintextMultipartyMult << std::endl;

    std::cout << "\n";

}