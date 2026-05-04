//
// Created by Lorenzo on 24/10/23.
//

#ifndef PAPERRESNET_FHECONTROLLER_H
#define PAPERRESNET_FHECONTROLLER_H

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include <thread>
#include "schemelet/rlwe-mp.h"
#include "math/hermite.h"
#include <functional>

#include "Utils.h"

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;

using namespace utils;

using Ptxt = Plaintext;
using Ctxt = Ciphertext<DCRTPoly>;

class FHEController {
    CryptoContext<DCRTPoly> context;

public:
    int circuit_depth;
    int num_slots;

    FHEController() {}

    /*
     * Context generating/loading stuff
     */
    void generate_context(bool serialize = false);
    void generate_context(int log_ring, int log_scale, int log_primes, int digits_hks, int cts_levels, int stc_levels, int relu_deg, bool serialize = false);
    void load_context(bool verbose = true);
    void test_context();

    /*
     * Generating bootstrapping and rotation keys stuff
     */
    void generate_bootstrapping_keys(int bootstrap_slots);
    void generate_rotation_keys(vector<int> rotations, bool serialize = false, string filename = "");
    void generate_bootstrapping_and_rotation_keys(vector<int> rotations,
                                                  int bootstrap_slots,
                                                  bool serialize,
                                                  const string& filename);


    void load_bootstrapping_and_rotation_keys(const string& filename, int bootstrap_slots, bool verbose);
    void load_rotation_keys(const string& filename, bool verbose);
    void clear_bootstrapping_and_rotation_keys(int bootstrap_num_slots);
    void clear_rotation_keys();
    void clear_context(int bootstrapping_key_slots);


    /*
     * CKKS Encoding/Decoding/Encryption/Decryption
     */
    Ptxt encode_int(const vector<int64_t>& vec, int level, int plaintext_num_slots);
    Ctxt encrypt_int(const vector<int64_t>& vec, int level = 0, int plaintext_num_slots = 0);
    Ptxt encode(const vector<double>& vec, int level, int plaintext_num_slots);
    Ptxt encode(double val, int level, int plaintext_num_slots);
    Ctxt encrypt(const vector<double>& vec, int level = 0, int plaintext_num_slots = 0);
    Ctxt encrypt_ptxt(const Ptxt& p);
    Ptxt decrypt(const Ctxt& c);
    vector<int64_t> decrypt_tovector(const Ctxt& c, int slots);


    /*
     * Homomorphic operations
     */
    Ctxt add(const Ctxt& c1, const Ctxt& c2);
    Ctxt mult(const Ctxt& c, double d);
    Ctxt mult(const Ctxt& c, const Ptxt& p);
    Ctxt func_bootstrap(const Ctxt& c, double scale, bool timing = false);
    Ctxt func_bootstrap(const Ctxt& c, double scale, int precision, bool timing = false);
    Ctxt bootstrap(const Ctxt& c, bool timing = false);
    Ctxt bootstrap(const Ctxt& c, int precision, bool timing = false);
    Ctxt relu(const Ctxt& c, double scale, bool timing = false);
    Ctxt relu_wide(const Ctxt& c, double a, double b, int degree, double scale, bool timing = false);

    /*
     * I/O
     */
    Ctxt read_input(const string& filename, double scale = 1);
    void print(const Ctxt& c, int slots = 0, string prefix = "");
    void print_padded(const Ctxt& c, int slots = 0, int padding = 1, string prefix = "");
    void print_min_max(const Ctxt& c);

    /*
     * Convolutional Neural Network functions
     */
    Ctxt convbn_initial(const Ctxt &in, double scale = 0.5, bool timing = false);
    Ctxt convbn(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    Ctxt convbn2(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    Ctxt convbn3(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    vector<Ctxt> convbn1632sx(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    vector<Ctxt> convbn1632dx(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    vector<Ctxt> convbn3264sx(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    vector<Ctxt> convbn3264dx(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);

    Ctxt downsample1024to256(const Ctxt& c1, const Ctxt& c2);
    Ctxt downsample256to64(const Ctxt &c1, const Ctxt &c2);

    Ctxt rotsum(const Ctxt &in, int slots);
    Ctxt rotsum_padded(const Ctxt &in, int slots);

    Ctxt repeat(const Ctxt &in, int slots);

    //TODO: studia sta roba
    Ctxt convbnV2(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    Ctxt convbn1632sxV2(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);
    Ctxt convbn1632dxV2(const Ctxt &in, int layer, int n, double scale = 0.5, bool timing = false);


    /*
     * Masking things
     */
    Ptxt gen_mask(int n, int level);
    Ptxt mask_first_n(int n, int level);
    Ptxt mask_second_n(int n, int level);
    Ptxt mask_first_n_mod(int n, int padding, int pos, int level);
    Ptxt mask_first_n_mod2(int n, int padding, int pos, int level);
    Ptxt mask_channel(int n, int level);
    Ptxt mask_channel_2(int n, int level);
    Ptxt mask_from_to(int from, int to, int level);

    Ptxt mask_mod(int n, int level, double custom_val);

    void bootstrap_precision(const Ctxt& c);
    int32_t levelsUsedBeforeBootstrap;

    int relu_degree = 119;
    string parameters_folder = "NO_FOLDER";

private:
    KeyPair<DCRTPoly> key_pair;
    vector<uint32_t> level_budget = {4, 4};

    // Mode-tracked bootstrap precomputations.
    // OpenFHE's m_bootPrecomMap[slots] can hold the precomputed plaintexts of either the classical
    // bootstrap (EvalBootstrapSetup) or the functional bootstrap (EvalFBTSetup) but not both at the
    // same time, since both setups overwrite the same map slot. We track which flavor is currently
    // active per slot count and re-run the appropriate setup only when the wrappers are about to
    // call the other flavor.
    enum class BootstrapMode { None, FBT, Classical };
    std::map<uint32_t, BootstrapMode> bootstrap_mode_per_slots;

    void ensure_fbt_setup(uint32_t slots);
    void ensure_classical_setup(uint32_t slots);
};


#endif //PAPERRESNET_FHECONTROLLER_H
