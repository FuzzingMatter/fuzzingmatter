#pragma once
#include "DeviceStateTracker.h"
#include "ForwardDeclarations.h"
#include "StatsMonitor.h"
#include "Utils.h"
#include <condition_variable>
#include <mutex>
namespace chip {
namespace fuzzing {

/**
 * @brief The status of the current fuzzer context. It represents the last event occurred in the context.
 *
 */
class ContextStatus
{
public:
    enum Status : uint8_t
    {
        INITIALIZED,
        NON_INVOKE_REQUEST,
        INVOKE_REQUEST,
        NON_INVOKE_RESPONSE,
        INVOKE_RESPONSE,
        SUBSCRIPTION_RESPONSE,
        TERMINATED
    };
    bool operator>=(Status rhs) { return static_cast<uint8_t>(mStatus) >= static_cast<uint8_t>(rhs); }
    bool operator<(Status rhs) { return static_cast<uint8_t>(mStatus) < static_cast<uint8_t>(rhs); }
    void operator=(Status rhs) { mStatus = rhs; }
    bool operator==(Status rhs) { return mStatus == rhs; }
    bool operator!=(Status rhs) { return mStatus != rhs; }
    uint8_t AsInteger() { return static_cast<uint8_t>(mStatus); }

private:
    Status mStatus = INITIALIZED;
};

struct FuzzerContext
{
    uint32_t id;
    ContextStatus status;
    chip::NodeId destination;
    std::string commandString;
    chip::Optional<chip::app::ConcreteCommandPath> commandPath = chip::NullOptional;
    CHIP_ERROR commandStatusResponse;
    types::AttributePathMap nonInvokeResponseData;
    std::shared_ptr<types::AnyType> invokeResponseData;
    std::vector<types::AttributePathMap> reportedData;
    DeviceStateTracker currentDeviceState;
    types::ExecutionStats executionStats;
    bool * waitingForResponse;
    bool waitingForReport = false;
};

class ContextManager
{
public:
    ContextManager() {}

    void Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse);
    CHIP_ERROR RequireResponse();
    CHIP_ERROR RequireSubscriptionReport();
    CHIP_ERROR NotifyResponse();

    bool WaitForResponse(std::chrono::steady_clock::time_point & waitingUntil);
    CHIP_ERROR WaitForSubscriptionReport(std::vector<types::AttributePathMap> * out);

    CHIP_ERROR OnInvokeRequest(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath);
    CHIP_ERROR OnInvokeResponse(CHIP_ERROR status, std::shared_ptr<types::AnyType> responseData);
    CHIP_ERROR OnNonInvokeRequest(chip::NodeId dst);
    CHIP_ERROR OnNonInvokeResponse(types::AttributePathMap reportedData);

    template <typename T>
    CHIP_ERROR GetResponseData(T * out);

    CHIP_ERROR OnSubscriptionReport(types::AttributePathMap reportedData);
    void NotifyCommandScheduledTime();

    void OnResponseTimeout();
    CHIP_ERROR Close(bool log = false);

    bool IsInitialized() { return mContext != nullptr; }
    void SetReportTimeout(std::chrono::milliseconds timeout) { mReportTimeout = timeout; }

private:
    std::unique_ptr<FuzzerContext> mContext     = nullptr;
    std::unique_ptr<FuzzerContext> mLastContext = nullptr;
    std::mutex * mContextMutex;
    std::condition_variable * mCvContextMutex;
    std::chrono::milliseconds mReportTimeout{ 250 };
    CHIP_ERROR EnsureContextValidity();
};

} // namespace fuzzing
} // namespace chip
