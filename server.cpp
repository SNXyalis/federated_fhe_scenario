//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Examples of threshold FHE for BGVrns, BFVrns and CKKS
 */

#include "openfhe.h"

using namespace lbcrypto;

void RunCKKS();

int main(int argc, char* argv[]) {

    std::cout << "\n=================RUNNING FOR CKKS=====================" << std::endl;

    RunCKKS();

    return 0;
}

void RunCKKS() {
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

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;
    KeyPair<DCRTPoly> kp3; //3rd party experiment 

    KeyPair<DCRTPoly> kpMultiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys =
        std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    std::cout << "Round 1 of key generation completed." << std::endl;


    std::cout << &kp1.publicKey << std::endl;
    std::cout << kp1.publicKey << std::endl;
    std::cout << cc->GetAllEvalMultKeys << std::endl;
    cc->SerializedObjectName
    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);
    kp3 = cc->MultipartyKeyGen(kp2.publicKey);

    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey2);

    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());


    std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
                 "into s_b*(s_a + s_b)..."
              << std::endl;
    //auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
    //auto evalMultCAC = cc->MultiMultEvalKey(kp3.secretKey, evalMultAC, kp3.publicKey->GetKeyTag());
    auto evalMultCABC = cc->MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());


    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysB, kp3.publicKey->GetKeyTag());

    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());
    auto evalSumKeysJoin2 = cc->MultiAddEvalSumKeys(evalSumKeysJoin, evalSumKeysC, kp3.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin2);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party A) started." << std::endl;

    std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..." << std::endl;
    //auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
    //auto evalMultAAC = cc->MultiMultEvalKey(kp1.secretKey, evalMultAC, kp3.publicKey->GetKeyTag());
    auto evalMultAABC = cc->MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
    auto evalMultBABC = cc->MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());

    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultCABC, evalMultABC->GetKeyTag());
    auto evalMultFinal2 = cc->MultiAddEvalMultKeys(evalMultFinal, evalMultBABC, evalMultABC->GetKeyTag());
    //auto evalMultFinal2 = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultCABC, evalMultABC->GetKeyTag());

    //auto evalMultFinal3 = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultABC->GetKeyTag());



    //cc->InsertEvalMultKey({evalMultFinal});
    cc->InsertEvalMultKey({evalMultFinal2});
    //cc->InsertEvalMultKey({evalMultFinal3});



    std::cout << "Round 3 of key generation completed." << std::endl;

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
    //Ciphertext<DCRTPoly> ciphertextAdd12;
    //Ciphertext<DCRTPoly> ciphertextAdd123;

    //Add Weights to Waggr
    Waggr  = cc->EvalAdd(ciphertext1, ciphertext2);
    Waggr = cc->EvalAdd(Waggr, ciphertext3);

    // Multiply Waggr by N**-1, where N is the number of clients
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

    // distributed decryption

    //Result after Sum of Weights
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({Waggr}, kp1.secretKey);

    auto ciphertextPartial2 = cc->MultipartyDecryptMain({Waggr}, kp2.secretKey);

    auto ciphertextPartial3 = cc->MultipartyDecryptMain({Waggr}, kp3.secretKey);


    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);
    partialCiphertextVec.push_back(ciphertextPartial3[0]);//

    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
    
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
    partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);
    partialCiphertextVecEvalSum.push_back(ciphertextPartial3[0]);

    plaintextMultipartyNew->SetLength(plaintext1->GetLength());

    std::cout << "\n Resulting Fused Plaintext: \n" << std::endl;
    std::cout << plaintextMultipartyNew << std::endl;

    std::cout << "\n";

    //Result after multiplication
    Plaintext plaintextMultipartyMult;

    ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1.secretKey);

    ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp2.secretKey);

    ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextMult}, kp3.secretKey);//


    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
    partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
    partialCiphertextVecMult.push_back(ciphertextPartial3[0]);//

    cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

    plaintextMultipartyMult->SetLength(plaintext1->GetLength());

    std::cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts Waggr "
                 "and 0.3333(1/3 clients): \n"
              << std::endl;
    std::cout << plaintextMultipartyMult << std::endl;

    std::cout << "\n";

}