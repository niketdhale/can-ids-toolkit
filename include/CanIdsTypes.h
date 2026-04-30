#pragma once
#include "CanTypes.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>

struct CanIdsResult {
    enum class Status { 
        Valid, 
        InvalidId, 
        InvalidDlc, 
        FrequencyViolation, 
        LengthViolation,
        Unknown 
    };
    Status status = Status::Unknown;
    std::string reason;
    bool should_forward = false;
};

struct CanIdsRule {
    uint32_t id;
    bool is_extended = false;
    std::vector<uint8_t> valid_dlcs;
    uint32_t min_interval_ms = 0;
    uint32_t max_payload_bytes = 8;
    bool enabled = true;
};

struct CanIdsStats {
    uint64_t total_frames = 0;
    uint64_t valid_frames = 0;
    uint64_t blocked_frames = 0;
    std::unordered_map<uint32_t, uint64_t> blocked_by_id;
};

using CanIdsAlertCallback = std::function<void(const CanFrame&, const CanIdsResult&)>;