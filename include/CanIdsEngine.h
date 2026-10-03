#pragma once
#include "CanIdsTypes.h"
#include <unordered_map>
#include <mutex>
#include <atomic>

class CanIdsEngine {
public:
    CanIdsEngine();
    ~CanIdsEngine();

    bool addRule(const CanIdsRule& rule);
    bool removeRule(uint32_t id, bool is_extended = false);
    std::vector<CanIdsRule> listRules() const;
    CanIdsResult validateFrame(const CanFrame& frame);
    CanIdsStats getStats() const;
    void resetStats();
    void setAlertCallback(CanIdsAlertCallback cb);
    void setEnabled(bool enabled);
    bool isEnabled() const;

private:
    mutable std::mutex m_mutex;  // ✅ FIXED: Added 'mutable' keyword
    std::atomic<bool> m_enabled{true};
    std::unordered_map<uint64_t, CanIdsRule> m_rules;
    std::unordered_map<uint64_t, uint64_t> m_last_rx_time;
    CanIdsStats m_stats;
    CanIdsAlertCallback m_alert_cb;

    static constexpr size_t kMaxBlockedIds = 1024;
    CanIdsResult validateLocked(const CanFrame& frame);
    void recordBlocked(uint32_t id);

    static uint64_t makeRuleKey(uint32_t id, bool is_extended);
    static bool isValidDlcClassic(uint8_t dlc);
    static bool isValidDlcFd(uint8_t dlc);
};