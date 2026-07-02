#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <algorithm>
#include <memory>
#include <iomanip>
#include <numeric>

// ---------------------------------------------------------
// DATA STRUCTURES
// ---------------------------------------------------------
// Feature Vector: [0] packet rate, [1] byte ratio, [2] port entropy
using Point = std::vector<double>;

// Euclidean distance helper
double euclideanDistance(const Point& a, const Point& b) {
    double sum = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        sum += (a[i] - b[i]) * (a[i] - b[i]);
    }
    return std::sqrt(sum);
}

// ---------------------------------------------------------
// 1. LOCAL OUTLIER FACTOR (LOF) IMPLEMENTATION
// ---------------------------------------------------------
class LocalOutlierFactor {
private:
    int k;
    std::vector<Point> data;

public:
    explicit LocalOutlierFactor(int k_neighbors) : k(k_neighbors) {}

    std::vector<double> fit_predict(const std::vector<Point>& input_data) {
        this->data = input_data;
        int n = data.size();
        std::vector<double> lof_scores(n, 0.0);
        std::vector<std::vector<int>> k_neighbors(n);
        std::vector<double> k_distances(n);

        // 1. Find k-distance and k-nearest neighbors for each point
        for (int i = 0; i < n; ++i) {
            std::vector<std::pair<double, int>> dists(n);
            for (int j = 0; j < n; ++j) {
                dists[j] = {euclideanDistance(data[i], data[j]), j};
            }
            // Partially sort to find the top k+1 closest (including self)
            std::nth_element(dists.begin(), dists.begin() + k + 1, dists.end());
            std::sort(dists.begin(), dists.begin() + k + 1);

            k_distances[i] = dists[k].first;
            for (int j = 1; j <= k; ++j) { // Start at 1 to skip self (distance 0)
                k_neighbors[i].push_back(dists[j].second);
            }
        }

        // 2. Calculate Local Reachability Density (LRD)
        std::vector<double> lrd(n, 0.0);
        for (int i = 0; i < n; ++i) {
            double reach_dist_sum = 0;
            for (int neighbor_idx : k_neighbors[i]) {
                double actual_dist = euclideanDistance(data[i], data[neighbor_idx]);
                reach_dist_sum += std::max(k_distances[neighbor_idx], actual_dist);
            }
            // Prevent division by zero
            lrd[i] = (reach_dist_sum > 0) ? ((double)k / reach_dist_sum) : 1e9;
        }

        // 3. Calculate LOF scores
        for (int i = 0; i < n; ++i) {
            double lrd_ratio_sum = 0;
            for (int neighbor_idx : k_neighbors[i]) {
                lrd_ratio_sum += lrd[neighbor_idx] / lrd[i];
            }
            lof_scores[i] = lrd_ratio_sum / k;
        }

        return lof_scores;
    }
};

// ---------------------------------------------------------
// 2. ISOLATION FOREST IMPLEMENTATION
// ---------------------------------------------------------
struct iNode {
    int split_feature = -1;
    double split_value = 0.0;
    std::unique_ptr<iNode> left = nullptr;
    std::unique_ptr<iNode> right = nullptr;
    int size = 0;
};

class IsolationForest {
private:
    int num_trees;
    int sample_size;
    int max_depth;
    std::vector<std::unique_ptr<iNode>> trees;

    // Average path length of unsuccessful search in BST
    double c(int n) const {
        if (n <= 1) return 0.0;
        if (n == 2) return 1.0;
        return 2.0 * (std::log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n);
    }

    std::unique_ptr<iNode> buildTree(const std::vector<Point>& data, std::vector<int>& indices, int current_depth, std::mt19937& rng) {
        auto node = std::make_unique<iNode>();
        node->size = indices.size();

        if (current_depth >= max_depth || indices.size() <= 1) return node;

        // Randomly select feature
        std::uniform_int_distribution<int> feat_dist(0, data[0].size() - 1);
        int f = feat_dist(rng);

        // Find min/max of selected feature
        double min_val = data[indices[0]][f];
        double max_val = data[indices[0]][f];
        for (int idx : indices) {
            min_val = std::min(min_val, data[idx][f]);
            max_val = std::max(max_val, data[idx][f]);
        }

        if (min_val == max_val) return node; // Cannot split

        // Randomly select split value
        std::uniform_real_distribution<double> split_dist(min_val, max_val);
        node->split_feature = f;
        node->split_value = split_dist(rng);

        std::vector<int> left_indices, right_indices;
        for (int idx : indices) {
            if (data[idx][f] < node->split_value) left_indices.push_back(idx);
            else right_indices.push_back(idx);
        }

        node->left = buildTree(data, left_indices, current_depth + 1, rng);
        node->right = buildTree(data, right_indices, current_depth + 1, rng);
        return node;
    }

    double pathLength(const Point& pt, const iNode* node, int current_length) const {
        if (node->left == nullptr && node->right == nullptr) {
            return current_length + c(node->size);
        }
        if (pt[node->split_feature] < node->split_value && node->left) {
            return pathLength(pt, node->left.get(), current_length + 1);
        } else if (node->right) {
            return pathLength(pt, node->right.get(), current_length + 1);
        }
        return current_length; // Fallback
    }

public:
    IsolationForest(int trees = 100, int samples = 256)
        : num_trees(trees), sample_size(samples) {
        max_depth = static_cast<int>(std::ceil(std::log2(sample_size)));
    }

    void fit(const std::vector<Point>& data) {
        std::mt19937 rng(42);
        trees.clear();
        int n = data.size();

        for (int i = 0; i < num_trees; ++i) {
            // Subsample data
            std::vector<int> indices(n);
            std::iota(indices.begin(), indices.end(), 0);
            std::shuffle(indices.begin(), indices.end(), rng);
            indices.resize(std::min(sample_size, n));

            trees.push_back(buildTree(data, indices, 0, rng));
        }
    }

    std::vector<double> predict(const std::vector<Point>& data) const {
        std::vector<double> scores(data.size(), 0.0);
        double avg_path_normalizer = c(sample_size);

        for (size_t i = 0; i < data.size(); ++i) {
            double avg_path_length = 0;
            for (const auto& tree : trees) {
                avg_path_length += pathLength(data[i], tree.get(), 0);
            }
            avg_path_length /= num_trees;

            // Calculate anomaly score: values close to 1 are anomalous
            scores[i] = std::pow(2.0, -(avg_path_length / avg_path_normalizer));
        }
        return scores;
    }
};

// ---------------------------------------------------------
// SIMULATED TRAFFIC LOG GENERATOR
// ---------------------------------------------------------
std::vector<Point> generateSimulatedTraffic(int num_samples, int num_anomalies) {
    std::vector<Point> data;
    std::mt19937 gen(1337);

    // Normal traffic (Gaussian distribution)
    std::normal_distribution<> pr_dist(500.0, 50.0);   // Packet Rate
    std::normal_distribution<> br_dist(1.5, 0.2);      // Byte Ratio
    std::normal_distribution<> pe_dist(0.8, 0.1);      // Port Entropy

    // Anomalous traffic (Wildly different distribution)
    std::uniform_real_distribution<> anom_pr(5000.0, 10000.0);
    std::uniform_real_distribution<> anom_br(5.0, 15.0);
    std::uniform_real_distribution<> anom_pe(2.0, 5.0);

    for (int i = 0; i < num_samples - num_anomalies; ++i) {
        data.push_back({pr_dist(gen), br_dist(gen), pe_dist(gen)});
    }
    for (int i = 0; i < num_anomalies; ++i) {
        data.push_back({anom_pr(gen), anom_br(gen), anom_pe(gen)});
    }

    // Shuffle the dataset so anomalies are randomly distributed
    std::shuffle(data.begin(), data.end(), gen);
    return data;
}

// ---------------------------------------------------------
// ENSEMBLE ENGINE & BENCHMARKING
// ---------------------------------------------------------
int main() {
    int total_samples = 10000;
    int true_anomalies = 50;

    std::cout << "--- ML-Based Anomaly Detection Engine ---" << std::endl;
    std::cout << "Generating " << total_samples << " simulated flow feature vectors..." << std::endl;

    auto data = generateSimulatedTraffic(total_samples, true_anomalies);

    // BENCHMARK LOF
    std::cout << "\n[1] Running Local Outlier Factor (LOF)..." << std::endl;
    auto start_lof = std::chrono::high_resolution_clock::now();

    LocalOutlierFactor lof(20); // k=20
    std::vector<double> lof_scores = lof.fit_predict(data);

    auto end_lof = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff_lof = end_lof - start_lof;
    std::cout << "    LOF execution time: " << diff_lof.count() << " seconds." << std::endl;

    // BENCHMARK iFOREST
    std::cout << "\n[2] Running Isolation Forest..." << std::endl;
    auto start_if = std::chrono::high_resolution_clock::now();

    IsolationForest iforest(100, 256); // 100 trees, 256 sample size
    iforest.fit(data);
    std::vector<double> iforest_scores = iforest.predict(data);

    auto end_if = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff_if = end_if - start_if;
    std::cout << "    iForest execution time: " << diff_if.count() << " seconds." << std::endl;

    // ENSEMBLE ALERTING
    std::cout << "\n[3] Correlating algorithms for ensemble alerting..." << std::endl;

    // Determine thresholds (Top 1% of scores)
    int threshold_idx = total_samples * 0.99;

    std::vector<double> sorted_lof = lof_scores;
    std::nth_element(sorted_lof.begin(), sorted_lof.begin() + threshold_idx, sorted_lof.end());
    double lof_threshold = sorted_lof[threshold_idx];

    std::vector<double> sorted_if = iforest_scores;
    std::nth_element(sorted_if.begin(), sorted_if.begin() + threshold_idx, sorted_if.end());
    double iforest_threshold = sorted_if[threshold_idx];

    int agreement_count = 0;
    for (int i = 0; i < total_samples; ++i) {
        bool lof_flag = lof_scores[i] >= lof_threshold;
        bool iforest_flag = iforest_scores[i] >= iforest_threshold;

        if (lof_flag && iforest_flag) {
            agreement_count++;
            std::cout << "    [CRITICAL ALERT] Flow ID " << std::setw(5) << i
                      << " | LOF Score: " << std::fixed << std::setprecision(2) << lof_scores[i]
                      << " | iForest Score: " << iforest_scores[i]
                      << " | Feats: (" << data[i][0] << ", " << data[i][1] << ", " << data[i][2] << ")" << std::endl;
        }
    }

    std::cout << "\nTotal flows flagged by BOTH algorithms: " << agreement_count << std::endl;
    std::cout << "Benchmark complete." << std::endl;

    return 0;
}