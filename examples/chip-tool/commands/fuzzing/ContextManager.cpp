#include "ContextManager.h"
#include "Fuzzer.h"
#include "StatsMonitor.h"
#include "Tuner.h"
#include "Utils.h"
#include <app/InteractionModelEngine.h>
#include <fstream>
#include <thread>

CHIP_ERROR fuzz::ContextManager::EnsureContextValidity()
{
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    return CHIP_NO_ERROR;
}

void fuzz::ContextManager::Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse)
{
    VerifyOrDieWithSave(cv != nullptr && mutex != nullptr && waitingForResponse != nullptr);
    std::unique_lock<std::mutex> lk(*mutex);
    auto fuzzer             = fuzz::Fuzzer::GetInstance();
    mContext                = std::make_unique<FuzzerContext>();
    mCvContextMutex         = cv;
    mContextMutex           = mutex;
    mContext->commandString = fuzzer->CurrentCommand();
    mContext->destination   = fuzzer->CurrentDestination();
    // Makes a copy of the current device state to be used for state dumping if required
    mContext->currentDeviceState = *fuzzer->GetDeviceStateTracker();
    if (fuzzer->CurrentAnalyzedPath().HasValidIds())
    {
        mContext->commandPath.SetValue(fuzzer->CurrentAnalyzedPath());
    }
    mContext->id                     = mLastContext ? ++(mLastContext->id) : 0;
    mContext->status                 = ContextStatus::INITIALIZED;
    mContext->executionStats.issTime = std::chrono::steady_clock::now();
    mContext->waitingForResponse     = waitingForResponse;
    *mContext->waitingForResponse    = true;
}

CHIP_ERROR fuzz::ContextManager::RequireResponse()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    *mContext->waitingForResponse = true;
    return CHIP_NO_ERROR;
}

void fuzz::ContextManager::NotifyCommandScheduledTime()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    mContext->executionStats.schTime = std::chrono::steady_clock::now();
}

CHIP_ERROR fuzz::ContextManager::OnInvokeRequest(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    auto fuzzer = fuzz::Fuzzer::GetInstance();
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    auto debugFileName = "flow_debug_" + std::to_string(dst) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open())
    {
        debugFile << fuzzer->CurrentCommand();
        if (!fuzzer->GetStatsMonitor()->HasExceededSubscriptionTimeoutsLimit(commandPath))
        {
            debugFile << " >>> GENERATES REPORT <<<";
        }
        debugFile << std::endl << "request" << std::endl;
        debugFile.close();
    }
#endif

    if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
    {
        fuzzer->GetTuner()->AddMessage(Tuner::MessageType::REQUEST);
    }
    ReturnErrorOnFailure(EnsureContextValidity());
    mContext->executionStats.txTime = std::chrono::steady_clock::now();
    mContext->destination           = dst;
    mContext->commandPath.SetValue(commandPath);
    mContext->commandString = fuzzer->CurrentCommand();

    ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to INVOKE_REQUEST.");
    mContext->status = ContextStatus::INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnNonInvokeRequest(chip::NodeId dst)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    auto fuzzer = fuzz::Fuzzer::GetInstance();
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    auto debugFileName = "flow_debug_" + std::to_string(dst) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open())
    {
        debugFile << fuzzer->CurrentCommand() << std::endl;
        debugFile << "request" << std::endl;
        debugFile.close();
    }
#endif
    ReturnErrorOnFailure(EnsureContextValidity());
    mContext->destination = dst;

    ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to NON_INVOKE_REQUEST.");
    mContext->status = ContextStatus::NON_INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

bool fuzz::ContextManager::WaitForResponse(std::chrono::steady_clock::time_point & waitingUntil)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    ChipLogDetail(chipToolFuzzing, "Waiting for response...");
    mContext->executionStats.waitForRxTime = std::chrono::steady_clock::now();
    return mCvContextMutex->wait_until(lk, waitingUntil, [this]() { return !(*mContext->waitingForResponse); });
}

CHIP_ERROR fuzz::ContextManager::OnInvokeResponse(CHIP_ERROR status, std::shared_ptr<types::AnyType> responseData)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    auto fuzzer = fuzz::Fuzzer::GetInstance();
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    std::string debugFileName = mContext ? "flow_debug_" + std::to_string(mContext->destination) + ".txt"
                                         : "flow_debug_" + std::to_string(mLastContext->destination) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open() && status != CHIP_ERROR_TIMEOUT)
    {
        debugFile << "response " << status.AsString(false) << std::endl;
        debugFile.close();
    }
#endif
    if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
    {
        fuzzer->GetTuner()->AddMessage(Tuner::MessageType::RESPONSE);
    }
    ReturnErrorOnFailure(EnsureContextValidity());

    mContext->executionStats.rxTime = std::chrono::steady_clock::now();
    mContext->commandStatusResponse = status;
    mContext->invokeResponseData    = responseData;
    // TODO: Problems!!!!!!!
    VerifyOrDieWithSave(mContext->commandPath.HasValue());
    auto cmdPath = mContext->commandPath.Value();
    if (status.IsIMStatus() &&
        chip::app::StatusIB(status).mStatus == chip::Protocols::InteractionModel::Status::NeedsTimedInteraction)
    {
        fuzzer->GetDeviceStateTracker()->WriteToCommandSpec(mContext->destination, cmdPath.mEndpointId, cmdPath.mClusterId,
                                                            cmdPath.mCommandId, types::Access::kTimed);
    }
    // TODO: is this correct?
    if (CHIP_NO_ERROR != status && fuzzer->CurrentMode() == FuzzerMode::TESTING)
    {
        types::FuzzerObservation observation = { mContext->commandString, cmdPath, mContext->commandStatusResponse,
                                                 mContext->invokeResponseData, mContext->reportedData };
        fuzz::Fuzzer::GetInstance()->GetStatsMonitor()->AddObservation(std::move(mContext->currentDeviceState), observation);
    }

    ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to INVOKE_RESPONSE.");

    mContext->status = ContextStatus::INVOKE_RESPONSE;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnNonInvokeResponse(types::AttributePathMap responseData)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    ReturnErrorOnFailure(EnsureContextValidity());
    VerifyOrReturnError(mContext->status == ContextStatus::NON_INVOKE_REQUEST, CHIP_FUZZER_ERROR_BAD_CONTEXT_STATE);
    mContext->nonInvokeResponseData = responseData;
    ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to NON_INVOKE_RESPONSE.");
    mContext->status = ContextStatus::NON_INVOKE_RESPONSE;
    return CHIP_NO_ERROR;
}

void fuzz::ContextManager::OnResponseTimeout()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    std::string debugFileName = mContext ? "flow_debug_" + std::to_string(mContext->destination) + ".txt"
                                         : "flow_debug_" + std::to_string(mLastContext->destination) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open())
    {
        debugFile << "timeout" << std::endl;
        debugFile.close();
    }
#endif
    ReturnOnFailure(EnsureContextValidity());
    auto fuzzer                               = fuzz::Fuzzer::GetInstance();
    mContext->executionStats.rxTime           = std::chrono::steady_clock::now();
    mContext->executionStats.responseTimedOut = true;
    mContext->commandStatusResponse           = CHIP_ERROR_TIMEOUT;

    if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
    {
        fuzzer->GetTuner()->AddMessage(Tuner::MessageType::RESPONSE);
    }

    ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to TERMINATED.");
    mContext->status = ContextStatus::TERMINATED;
}

CHIP_ERROR fuzz::ContextManager::RequireSubscriptionReport()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);

    auto fuzzer       = fuzz::Fuzzer::GetInstance();
    auto fuzzerPhase  = fuzzer->CurrentPhase();
    auto statsMonitor = fuzzer->GetStatsMonitor();

    bool reportsEnabled  = fuzzerPhase == FuzzerPhase::TESTING;
    bool isInvokeCommand = mContext->commandPath.HasValue();
    if (isInvokeCommand && reportsEnabled && !statsMonitor->HasExceededSubscriptionTimeoutsLimit(mContext->commandPath.Value()))
        mContext->waitingForReport = true;

    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::WaitForSubscriptionReport(std::vector<types::AttributePathMap> * out)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    CHIP_ERROR err = CHIP_NO_ERROR;
    auto fuzzer    = fuzz::Fuzzer::GetInstance();
    ReturnErrorOnFailure(EnsureContextValidity());
    if (mContext->waitingForReport && mContext->status == ContextStatus::INVOKE_RESPONSE)
    {
        mContext->executionStats.waitForRepRxTime = std::chrono::steady_clock::now();
        bool timedOut                             = false;
        while (!timedOut)
        {
            ChipLogDetail(chipToolFuzzing, "Waiting for subscription data...");
            mContext->waitingForReport         = true;
            timedOut                           = !mCvContextMutex->wait_until(lk, std::chrono::steady_clock::now() + mReportTimeout,
                                                                              [this] { return !mContext->waitingForReport; });
            mContext->executionStats.repRxTime = std::chrono::steady_clock::now();
        }
        mContext->status           = ContextStatus::SUBSCRIPTION_RESPONSE;
        mContext->waitingForReport = false;
        ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to SUBSCRIPTION_RESPONSE.");

        if (mContext->reportedData.empty())
        {
            ChipLogError(chipToolFuzzing, "No subscription data was received in time.");
            fuzzer->GetStatsMonitor()->IncrementSubscriptionTimeouts(mContext->commandPath.Value());
            mContext->executionStats.subscriptionTimedOut = true;
            err                                           = CHIP_FUZZER_ERROR_SUBSCRIPTION_RESPONSE_TIMEOUT;
        }
        else
        {
            ChipLogDetail(chipToolFuzzing, "Received %zu subscription data reports", mContext->reportedData.size());
            ChipLogDetail(chipToolFuzzing, "Resetting subscription timeouts for command (%d, %d, %d)",
                          mContext->commandPath.Value().mEndpointId, mContext->commandPath.Value().mClusterId,
                          mContext->commandPath.Value().mCommandId);
            fuzzer->GetStatsMonitor()->ResetSubscriptionTimeouts(mContext->commandPath.Value());
            mContext->executionStats.subscriptionTimedOut = false;
            if (out)
                *out = mContext->reportedData;
        }

        if (fuzzer->CurrentMode() == FuzzerMode::TESTING)
        {
            types::FuzzerObservation observation = { mContext->commandString, mContext->commandPath.Value(),
                                                     mContext->commandStatusResponse, mContext->invokeResponseData,
                                                     mContext->reportedData };
            fuzzer->GetStatsMonitor()->AddObservation(std::move(mContext->currentDeviceState), observation);
        }
    }

    return err;
}

CHIP_ERROR fuzz::ContextManager::OnSubscriptionReport(types::AttributePathMap reportedData)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    auto fuzzer    = fuzz::Fuzzer::GetInstance();
    CHIP_ERROR err = CHIP_NO_ERROR;
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    std::string debugFileName = mContext ? "flow_debug_" + std::to_string(mContext->destination) + ".txt"
                                         : "flow_debug_" + std::to_string(mLastContext->destination) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open())
    {
        debugFile << "report\t";
        for (const auto & [path, value] : reportedData)
        {
            if (std::holds_alternative<ContainerType>(value))
                continue;
            debugFile << "(0x" << std::hex << path.mEndpointId << " 0x" << path.mClusterId << " 0x" << path.mAttributeId << ") = ";
            debugFile << Visitors::AttributeValueAsString(value) << ", ";
        }
    }
#endif
    if (CHIP_NO_ERROR == (err = EnsureContextValidity()))
    {
        if (mContext->status == ContextStatus::NON_INVOKE_RESPONSE && !mContext->commandPath.HasValue())
        {
            ChipLogDetail(chipToolFuzzing, "Skipping report coming from subscription establishment");
        }
        else if (mContext->commandPath.HasValue() && mContext->status == ContextStatus::INVOKE_RESPONSE)
        {
            ChipLogProgress(chipToolFuzzing, "Subscription data received");
            mContext->reportedData.push_back(reportedData);
            if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
            {
                fuzzer->GetTuner()->AddMessage(Tuner::MessageType::REPORT);
            }
        }
        else
        {
            // TODO: Why can we get here?
            err = CHIP_FUZZER_ERROR_BAD_CONTEXT_STATE;
        }
    }

    // If this is true, a report came before the request AND no context was active, so we can avoid invalidating the entire context
    // and just consider the report as orphan
    if (CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT == err)
    {
        ChipLogError(chipToolFuzzing, "Orphan report received but no context is active. Ignoring report data.");
        fuzzer->GetStatsMonitor()->TrackOrphanReport();
        if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
        {
            fuzzer->GetTuner()->AddMessage(Tuner::MessageType::REPORT);
        }
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
        if (debugFile.is_open())
        {
            debugFile << "[ORPHAN TYPE 1]" << std::endl;
            debugFile.close();
        }
#endif
        return err;
    }
    // If this is true, the context is active but the report was out-of-sequence (before the request or before the response), so we
    // invalidate the context data. The test will be tracked as invalid in the Close() method
    else if (CHIP_NO_ERROR != err)
    {
        ChipLogError(chipToolFuzzing, "Orphan report received. Ignoring report data");
        fuzzer->GetStatsMonitor()->TrackOrphanReport();
        if (fuzzer->CurrentMode() == FuzzerMode::TUNING)
        {
            fuzzer->GetTuner()->AddMessage(Tuner::MessageType::REPORT);
        }
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
        if (debugFile.is_open())
        {
            debugFile << "[ORPHAN TYPE 2]";
        }
#endif
    }

#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    if (debugFile.is_open())
    {
        debugFile << std::endl;
        debugFile.close();
    }
#endif

    mContext->waitingForReport = false;
    // Notification required because sender is blocked on wait_until() inside WaitForSubscriptionReport() method
    mCvContextMutex->notify_all();
    return CHIP_NO_ERROR;
}

template <>
CHIP_ERROR fuzz::ContextManager::GetResponseData(types::AnyType * out)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrDieWithSave(out);
    *out = mContext->invokeResponseData ? *mContext->invokeResponseData : std::monostate{};
    return CHIP_NO_ERROR;
}

template <>
CHIP_ERROR fuzz::ContextManager::GetResponseData(types::AttributePathMap * out)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrDieWithSave(out);
    *out = mContext->nonInvokeResponseData;
    return CHIP_NO_ERROR;
}

template <typename T>
CHIP_ERROR fuzz::ContextManager::GetResponseData(T * out)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR fuzz::ContextManager::Close(bool log)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
#if CHIP_FUZZING_ENABLE_CONTEXT_FLOW_DEBUG
    std::string debugFileName = mContext ? "flow_debug_" + std::to_string(mContext->destination) + ".txt"
                                         : "flow_debug_" + std::to_string(mLastContext->destination) + ".txt";
    std::ofstream debugFile(debugFileName, std::ios::app);
    if (debugFile.is_open())
    {
        debugFile << "---" << std::endl;
        debugFile.close();
    }
#endif
    auto statsMonitor = fuzz::Fuzzer::GetInstance()->GetStatsMonitor();

    VerifyOrDieWithSave(mContext);
    if (mContext->status != ContextStatus::TERMINATED)
    {
        ChipLogProgress(chipToolFuzzing, "Moving fuzzer context state to TERMINATED.");
        mContext->status = ContextStatus::TERMINATED;
    }

    mContext->executionStats.finishTime = std::chrono::steady_clock::now();

    if (log)
        statsMonitor->TrackStatsFromContext(*mContext);

    mLastContext = std::make_unique<FuzzerContext>(*mContext);
    mContext.reset();
    mContext = nullptr;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::NotifyResponse()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    ChipLogDetail(chipToolFuzzing, "Stopped waiting for response.");
    *mContext->waitingForResponse = false;
    mCvContextMutex->notify_all();
    return CHIP_NO_ERROR;
}
