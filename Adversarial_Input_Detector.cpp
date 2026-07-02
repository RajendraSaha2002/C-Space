#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <algorithm>

// Hyperparameters
const int INPUT_SIZE = 8;     // 8-byte sequence sample
const int HIDDEN_SIZE = 16;   // Hidden layer units
const int OUTPUT_SIZE = 1;    // Binary classification (0: Benign, 1: Malicious)
const float LR = 0.1f;        // Learning rate for training
const int EPOCHS = 1000;      // Training epochs

// Activation function
inline float sigmoid(float x) {
    return 1.0f / (1.0f + std::exp(-x));
}

// Structure to hold our Neural Network parameters
struct NeuralNetwork {
    std::vector<std::vector<float>> W1; // Weights Input -> Hidden [HIDDEN_SIZE][INPUT_SIZE]
    std::vector<float> b1;              // Bias Hidden [HIDDEN_SIZE]
    std::vector<float> W2;              // Weights Hidden -> Output [HIDDEN_SIZE]
    float b2;                           // Bias Output

    NeuralNetwork() {
        // Initialize weights with small random numbers
        std::srand(42); // Seed for reproducibility
        W1.resize(HIDDEN_SIZE, std::vector<float>(INPUT_SIZE));
        b1.resize(HIDDEN_SIZE, 0.0f);
        W2.resize(HIDDEN_SIZE);
        b2 = 0.0f;

        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            for (int i = 0; i < INPUT_SIZE; ++i) {
                W1[j][i] = ((float)std::rand() / RAND_MAX) * 0.4f - 0.2f;
            }
            W2[j] = ((float)std::rand() / RAND_MAX) * 0.4f - 0.2f;
        }
    }

    // Forward propagation
    float forward(const std::vector<float>& x, std::vector<float>& h) const {
        // Input -> Hidden
        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            float sum = b1[j];
            for (int i = 0; i < INPUT_SIZE; ++i) {
                sum += x[i] * W1[j][i];
            }
            h[j] = sigmoid(sum);
        }

        // Hidden -> Output
        float sum_out = b2;
        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            sum_out += h[j] * W2[j];
        }
        return sigmoid(sum_out);
    }

    // Standard Backpropagation to train the network
    void train(const std::vector<float>& x, float y_true) {
        std::vector<float> h(HIDDEN_SIZE);
        float y_pred = forward(x, h);

        // Mean Squared Error derivative: dL/dy_pred = y_pred - y_true
        float dL_dy = y_pred - y_true;
        float dy_dz2 = y_pred * (1.0f - y_pred);
        float delta2 = dL_dy * dy_dz2;

        // Hidden Layer Deltas
        std::vector<float> delta1(HIDDEN_SIZE);
        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            float dh_dz1 = h[j] * (1.0f - h[j]);
            delta1[j] = delta2 * W2[j] * dh_dz1;
        }

        // Update Weights and Biases (SGD)
        b2 -= LR * delta2;
        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            W2[j] -= LR * delta2 * h[j];
            b1[j] -= LR * delta1[j];
            for (int i = 0; i < INPUT_SIZE; ++i) {
                W1[j][i] -= LR * delta1[j] * x[i];
            }
        }
    }

    // Computes gradient of Loss w.r.t Input (Required for FGSM)
    std::vector<float> compute_input_gradient(const std::vector<float>& x, float y_target) const {
        std::vector<float> h(HIDDEN_SIZE);
        float y_pred = forward(x, h);

        float dL_dy = y_pred - y_target;
        float dy_dz2 = y_pred * (1.0f - y_pred);
        float delta2 = dL_dy * dy_dz2;

        std::vector<float> delta1(HIDDEN_SIZE);
        for (int j = 0; j < HIDDEN_SIZE; ++j) {
            delta1[j] = delta2 * W2[j] * (h[j] * (1.0f - h[j]));
        }

        std::vector<float> grad_x(INPUT_SIZE, 0.0f);
        for (int i = 0; i < INPUT_SIZE; ++i) {
            for (int j = 0; j < HIDDEN_SIZE; ++j) {
                grad_x[i] += delta1[j] * W1[j][i];
            }
        }
        return grad_x;
    }
};

// --- FGSM Adversarial Attack Implementation ---
std::vector<float> fgsm_attack(const NeuralNetwork& nn, const std::vector<float>& x, float y_true, float epsilon) {
    std::vector<float> grad = nn.compute_input_gradient(x, y_true);
    std::vector<float> x_adv(INPUT_SIZE);

    for (int i = 0; i < INPUT_SIZE; ++i) {
        // Shift input in the direction of increasing loss
        float sign = (grad[i] > 0) ? 1.0f : ((grad[i] < 0) ? -1.0f : 0.0f);
        x_adv[i] = x[i] + epsilon * sign;
        // Clip to valid byte scale boundaries [0.0, 1.0]
        x_adv[i] = std::max(0.0f, std::min(1.0f, x_adv[i]));
    }
    return x_adv;
}

// --- Feature-Squeezing Defense Layer ---
// Reduces float bit-depth/levels to eliminate minor adversarial perturbations
std::vector<float> feature_squeeze(const std::vector<float>& x, int levels) {
    std::vector<float> squeezed(INPUT_SIZE);
    for (int i = 0; i < INPUT_SIZE; ++i) {
        squeezed[i] = std::round(x[i] * (levels - 1)) / (levels - 1);
    }
    return squeezed;
}

int main() {
    NeuralNetwork nn;

    // 1. Generate Synthetic Byte-Sequence Dataset (Normalized between 0.0 and 1.0)
    // Benign samples have lower average byte values; Malicious have specific high spikes
    std::vector<std::vector<float>> train_X = {
        {0.1f, 0.2f, 0.1f, 0.3f, 0.2f, 0.1f, 0.2f, 0.1f}, // Benign
        {0.8f, 0.9f, 0.7f, 0.8f, 0.9f, 0.8f, 0.7f, 0.9f}, // Malicious
        {0.2f, 0.1f, 0.3f, 0.2f, 0.1f, 0.2f, 0.1f, 0.3f}, // Benign
        {0.9f, 0.7f, 0.8f, 0.9f, 0.6f, 0.8f, 0.9f, 0.7f}, // Malicious
        {0.1f, 0.1f, 0.2f, 0.2f, 0.1f, 0.3f, 0.1f, 0.2f}, // Benign
        {0.7f, 0.8f, 0.9f, 0.8f, 0.8f, 0.9f, 0.7f, 0.8f}  // Malicious
    };
    std::vector<float> train_Y = {0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f};

    // 2. Train the Neural Network Classifier
    std::cout << "[*] Training neural network classifier..." << std::endl;
    for (int epoch = 0; epoch < EPOCHS; ++epoch) {
        for (size_t i = 0; i < train_X.size(); ++i) {
            nn.train(train_X[i], train_Y[i]);
        }
    }
    std::cout << "[+] Training Complete.\n" << std::endl;

    // 3. Evaluate and Prepare Test Set
    // We choose a clear Malicious sequence sample to test attack and defense metrics
    std::vector<float> clean_input = {0.75f, 0.85f, 0.80f, 0.90f, 0.70f, 0.85f, 0.80f, 0.90f}; // Target: Malicious (1.0)
    float true_label = 1.0f;

    std::vector<float> dummy_h(HIDDEN_SIZE);
    float clean_pred = nn.forward(clean_input, dummy_h);
    std::cout << "--- Baseline Assessment ---" << std::endl;
    std::cout << "Clean Input Prediction (Confidence): " << std::fixed << std::setprecision(4) << clean_pred
              << " -> " << (clean_pred >= 0.5f ? "Malicious" : "Benign") << std::endl;

    // 4. Execute FGSM Attack
    float epsilon = 0.25f; // Perturbation size
    std::vector<float> adv_input = fgsm_attack(nn, clean_input, true_label, epsilon);
    float adv_pred = nn.forward(adv_input, dummy_h);

    std::cout << "\n--- FGSM Attack Execution (Epsilon: " << epsilon << ") ---" << std::endl;
    std::cout << "Adversarial Input Prediction:        " << adv_pred
              << " -> " << (adv_pred >= 0.5f ? "Malicious" : "Benign") << std::endl;
    if (adv_pred < 0.5f) {
        std::cout << "[!] Attack Success: Model was successfully fooled into classifying malicious payload as Benign!" << std::endl;
    }

    // 5. Apply Feature Squeezing Defense Layer & Measure Metrics
    // Squeeze features into 4 discrete levels (2-bit depth equivalents)
    int squeeze_levels = 4;
    std::vector<float> squeezed_clean = feature_squeeze(clean_input, squeeze_levels);
    std::vector<float> squeezed_adv = feature_squeeze(adv_input, squeeze_levels);

    float clean_squeezed_pred = nn.forward(squeezed_clean, dummy_h);
    float adv_squeezed_pred = nn.forward(squeezed_adv, dummy_h);

    // Feature Squeezing Framework detects manipulation via L1 prediction variance shift:
    // | Prediction(Original) - Prediction(Squeezed) | > Detection Threshold
    float detection_threshold = 0.15f;
    float clean_variance = std::abs(clean_pred - clean_squeezed_pred);
    float adv_variance = std::abs(adv_pred - adv_squeezed_pred);

    bool clean_detected = clean_variance > detection_threshold;
    bool adv_detected = adv_variance > detection_threshold;

    std::cout << "\n--- Feature-Squeezing Defense Metrics ---" << std::endl;
    std::cout << "Clean Input Prediction Variance: " << clean_variance << std::endl;
    std::cout << "Adversarial Input Variance:       " << adv_variance << std::endl;
    std::cout << "Detection Threshold Set To:       " << detection_threshold << std::endl;
    std::cout << "---------------------------------------" << std::endl;
    std::cout << "False Positive Flagged on Clean Data:  " << (clean_detected ? "YES" : "NO") << std::endl;
    std::cout << "Adversarial Attack Successfully Caught: " << (adv_detected ? "YES" : "NO") << std::endl;

    // Compute Detection Rate Contextual Summary
    float detection_rate = adv_detected ? 100.0f : 0.0f;
    std::cout << "\nFinal Defense Layer Evaluation -> Detection Rate: " << detection_rate << "%" << std::endl;

    return 0;
}