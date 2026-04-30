#include "../../include/CanIdsEngine.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>

static std::string hexDump(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    return oss.str();
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
            std::string param;
            while (iss >> param) {
                auto eq = param.find('=');
                if (eq == std::string::npos) continue;
                std::string k = param.substr(0, eq);
                std::string v = param.substr(eq + 1);
                if (k == "id") rule.id = std::stoul(v, nullptr, 16);
                else if (k == "ext") rule.is_extended = (v == "1");
                else if (k == "dlc") {
                    std::istringstream ss(v); std::string b;
                    while (std::getline(ss, b, ',')) rule.valid_dlcs.push_back(static_cast<uint8_t>(std::stoul(b)));
                }
                else if (k == "interval") rule.min_interval_ms = std::stoul(v);
                else if (k == "maxpay") rule.max_payload_bytes = std::stoul(v);
            }
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
            frame.id = std::stoul(raw.substr(0, hash), nullptr, 16);
            std::istringstream ds(raw.substr(hash+1)); std::string b;
            while (ds >> std::hex >> b) if(b.size()==2) frame.data.push_back(static_cast<uint8_t>(std::stoul(b,nullptr,16)));
            frame.timestamp_ns = std::chrono::steady_clock::now().time_since_epoch().count();
            frame.is_fd = frame.data.size() > 8;

            auto res = ids.validateFrame(frame);
            if (monitor_on || res.status != CanIdsResult::Status::Valid) {
                std::cout << "[" << (res.should_forward ? "PASS" : "BLOCK") << "] ID=0x" << std::hex << frame.id << std::dec
                          << " DLC=" << frame.data.size() << " Reason=" << res.reason << "\n";
            }
        }
        else { std::cout << "[?] Unknown command\n"; }
    }
    std::cout << "Shutdown complete.\n";
    return 0;
}