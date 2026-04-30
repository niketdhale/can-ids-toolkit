#include "CanIdsEngine.h"
#include <chrono>
#include <algorithm>

CanIdsEngine::CanIdsEngine() = default;
CanIdsEngine::~CanIdsEngine() = default;

uint64_t CanIdsEngine::makeRuleKey(uint32_t id, bool is_extended) {
    return (static_cast<uint64_t>(id) << 1) | (is_extended ? 1 : 0);
}

bool CanIdsEngine::isValidDlcClassic(uint8_t dlc) { return dlc <= 8; }

bool CanIdsEngine::isValidDlcFd(uint8_t dlc) {
    constexpr uint8_t valid[] = {0,1,2,3,4,5,6,7,8,12,16,20,24,32,48,64};
    return std::find(std::begin(valid), std::end(valid), dlc) != std::end(valid);
}

bool CanIdsEngine::addRule(const CanIdsRule& rule) {
    if (!rule.enabled || rule.valid_dlcs.empty() || rule.max_payload_bytes > 64) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_rules[makeRuleKey(rule.id, rule.is_extended)] = rule;
    return true;
}

bool CanIdsEngine::removeRule(uint32_t id, bool is_extended) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_rules.erase(makeRuleKey(id, is_extended)) > 0;
}

std::vector<CanIdsRule> CanIdsEngine::listRules() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CanIdsRule> out;
    out.reserve(m_rules.size());
    for (const auto& [_, r] : m_rules) out.push_back(r);
    return out;
}

CanIdsResult CanIdsEngine::validateFrame(const CanFrame& frame) {
    CanIdsResult res;
    if (!m_enabled) { res.status = CanIdsResult::Status::Valid; res.should_forward = true; return res; }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_stats.total_frames++;
    auto key = makeRuleKey(frame.id, frame.is_extended);
    auto it = m_rules.find(key);

    if (it == m_rules.end()) {
        res.status = CanIdsResult::Status::InvalidId;
        res.reason = "Unauthorized CAN ID";
        res.should_forward = false;
        m_stats.blocked_frames++;
        m_stats.blocked_by_id[frame.id]++;
        return res;
    }

    const auto& rule = it->second;
    uint8_t dlc = static_cast<uint8_t>(frame.data.size());
    bool dlc_ok = frame.is_fd ? isValidDlcFd(dlc) : isValidDlcClassic(dlc);

    if (!dlc_ok || std::find(rule.valid_dlcs.begin(), rule.valid_dlcs.end(), dlc) == rule.valid_dlcs.end()) {
        res.status = CanIdsResult::Status::InvalidDlc;
        res.reason = "Invalid DLC " + std::to_string(dlc);
        res.should_forward = false;
        m_stats.blocked_frames++;
        m_stats.blocked_by_id[frame.id]++;
        return res;
    }

    if (frame.data.size() > rule.max_payload_bytes) {
        res.status = CanIdsResult::Status::LengthViolation;
        res.reason = "Payload exceeds max " + std::to_string(rule.max_payload_bytes);
        res.should_forward = false;
        m_stats.blocked_frames++;
        m_stats.blocked_by_id[frame.id]++;
        return res;
    }

    if (rule.min_interval_ms > 0) {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto last_it = m_last_rx_time.find(key);
        if (last_it != m_last_rx_time.end()) {
            uint64_t delta = now - last_it->second;
            if (delta < rule.min_interval_ms * 1000000ULL) {
                res.status = CanIdsResult::Status::FrequencyViolation;
                res.reason = "Frame rate exceeded";
                res.should_forward = false;
                m_stats.blocked_frames++;
                m_stats.blocked_by_id[frame.id]++;
                return res;
            }
        }
        m_last_rx_time[key] = now;
    }

    res.status = CanIdsResult::Status::Valid;
    res.should_forward = true;
    m_stats.valid_frames++;
    return res;
}

CanIdsStats CanIdsEngine::getStats() const { std::lock_guard<std::mutex> lock(m_mutex); return m_stats; }
void CanIdsEngine::resetStats() { std::lock_guard<std::mutex> lock(m_mutex); m_stats = CanIdsStats{}; m_last_rx_time.clear(); }
void CanIdsEngine::setAlertCallback(CanIdsAlertCallback cb) { std::lock_guard<std::mutex> lock(m_mutex); m_alert_cb = std::move(cb); }
void CanIdsEngine::setEnabled(bool enabled) { std::lock_guard<std::mutex> lock(m_mutex); m_enabled = enabled; }
bool CanIdsEngine::isEnabled() const { return m_enabled; }