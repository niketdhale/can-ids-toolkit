#include "../../include/CanIdsEngine.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cctype>
#include <limits>

static std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    return oss.str();
}

static bool parseUnsigned(const std::string& v, int base, unsigned long long max, unsigned long long& out) {
    if (v.empty() || !std::isalnum(static_cast<unsigned char>(v[0]))) return false;
    try {
        size_t pos = 0;
        out = std::stoull(v, &pos, base);
        return pos == v.size() && out <= max;
    } catch (const std::exception&) { return false; }
}

static bool parseHexPayload(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2 != 0 || s.size() > 128) return false;
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned long long b;
        if (!std::isxdigit(static_cast<unsigned char>(s[i])) || !std::isxdigit(static_cast<unsigned char>(s[i+1]))) return false;
        parseUnsigned(s.substr(i, 2), 16, 0xFF, b);
        out.push_back(static_cast<uint8_t>(b));
    }
    return true;
}

int main() {
    CanIdsEngine ids;
    bool monitor_on = false;

    std::cout << "=== CAN IDS Toolkit ===\n"
              << "Commands: enable, disable, add, list, stats, clear, simulate, quit\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit") break;
        else if (cmd == "enable") { ids.setEnabled(true); std::cout << "[IDS] Enabled\n"; }
        else if (cmd == "disable") { ids.setEnabled(false); std::cout << "[IDS] Disabled\n"; }
        else if (cmd == "add") {
            CanIdsRule rule{};
            std::string param, err;
            bool have_id = false;
            unsigned long long n;
            while (err.empty() && iss >> param) {
                auto eq = param.find('=');
                if (eq == std::string::npos) continue;
                std::string k = param.substr(0, eq);
                std::string v = param.substr(eq + 1);
                if (k == "id") {
                    if (!parseUnsigned(v, 16, 0x1FFFFFFF, n)) err = "bad id";
                    else { rule.id = static_cast<uint32_t>(n); have_id = true; }
                }
                else if (k == "ext") rule.is_extended = (v == "1");
                else if (k == "dlc") {
                    std::istringstream ss(v); std::string b;
                    while (err.empty() && std::getline(ss, b, ',')) {
                        if (!parseUnsigned(b, 10, 64, n)) err = "bad dlc";
                        else rule.valid_dlcs.push_back(static_cast<uint8_t>(n));
                    }
                }
                else if (k == "interval") {
                    if (!parseUnsigned(v, 10, std::numeric_limits<uint32_t>::max(), n)) err = "bad interval";
                    else rule.min_interval_ms = static_cast<uint32_t>(n);
                }
                else if (k == "maxpay") {
                    if (!parseUnsigned(v, 10, 64, n)) err = "bad maxpay";
                    else rule.max_payload_bytes = static_cast<uint32_t>(n);
                }
            }
            if (err.empty() && !have_id) err = "id= required";
            if (!err.empty()) { std::cout << "[IDS ERR] " << err << "\n"; continue; }
            rule.enabled = true;
            std::cout << (ids.addRule(rule) ? "[IDS] Rule added\n" : "[IDS ERR] Invalid rule\n");
        }
        else if (cmd == "list") {
            auto rules = ids.listRules();
            std::cout << "[IDS] Rules: " << rules.size() << "\n";
            for (const auto& r : rules) {
                std::cout << "  ID=0x" << std::hex << r.id << std::dec << " DLCs=[";
                for (size_t i=0; i<r.valid_dlcs.size(); ++i) {
                    std::cout << static_cast<int>(r.valid_dlcs[i]) << (i+1<r.valid_dlcs.size()? ",":"");
                }
                std::cout << "] interval=" << r.min_interval_ms << "ms\n";
            }
        }
        else if (cmd == "stats") {
            auto s = ids.getStats();
            std::cout << "[IDS] Total=" << s.total_frames << " Valid=" << s.valid_frames << " Blocked=" << s.blocked_frames << "\n";
            if (!s.blocked_by_id.empty()) {
                std::cout << "  Blocked by ID:\n";
                for (const auto& [id, c] : s.blocked_by_id) std::cout << "    0x" << std::hex << id << std::dec << ": " << c << "\n";
            }
        }
        else if (cmd == "clear") { ids.resetStats(); std::cout << "[IDS] Stats cleared\n"; }
        else if (cmd == "monitor") { monitor_on = true; std::cout << "[Monitor] ON\n"; }
        else if (cmd == "simulate") {
            std::string raw; iss >> raw;
            auto hash = raw.find('#');
            if (hash == std::string::npos) { std::cout << "[ERR] Format: simulate ID#DATA\n"; continue; }
            CanFrame frame{};
            unsigned long long fid;
            if (!parseUnsigned(raw.substr(0, hash), 16, 0x1FFFFFFF, fid)) { std::cout << "[ERR] Invalid ID\n"; continue; }
            frame.id = static_cast<uint32_t>(fid);
            frame.is_extended = frame.id > 0x7FF;
            if (!parseHexPayload(raw.substr(hash+1), frame.data) || frame.data.size() > 64) { std::cout << "[ERR] Invalid payload (even-length hex, max 64 bytes)\n"; continue; }
            frame.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
            frame.is_fd = frame.data.size() > 8;

            auto res = ids.validateFrame(frame);
            if (monitor_on || res.status != CanIdsResult::Status::Valid) {
                std::cout << "[" << (res.should_forward ? "PASS" : "BLOCK") << "] ID=0x" << std::hex << frame.id << std::dec
                          << " DLC=" << frame.data.size() << " Reason=" << res.reason << " Data=" << hexDump(frame.data) << "\n";
            }
        }
        else { std::cout << "[?] Unknown command\n"; }
    }
    std::cout << "Shutdown complete.\n";
    return 0;
}