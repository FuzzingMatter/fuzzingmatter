#pragma once
#include "CallbackInterceptor.h"
#include "ContextManager.h"
#include "DeviceStateTracker.h"
#include "ForwardDeclarations.h"
#include "OutputLogger.h"
#include "StatsMonitor.h"
#include "Tuner.h"
#include <nlassert.h>

namespace chip {
namespace fuzzing {

#define VerifyOrDieWithSave(aCondition)                                                                                            \
    nlABORT_ACTION(aCondition, LogErrorOnFailure(::chip::fuzzing::Fuzzer::GetInstance()->GetStatsMonitor()->SaveData()))

enum class FuzzerPhase : uint8_t
{
    INITIALIZATION,
    ACQUISITION,
    TESTING,
};
enum class FuzzerMode : uint8_t
{
    TESTING,
    REPLICATION,
    TUNING,
};
/**
 * @brief Generates mutated commands to test the CHIP device's behavior, as well as
 * saving the valid ones as future reference.
 *
 * This class is the starting point for response data analysis coming from the response
 * callbacks.
 *
 * There can be only one instance of the Fuzzer class, which is created by the FuzzingStartCommand class.
 */
class Fuzzer
{
public:
    static Fuzzer * GetInstance(std::function<Fuzzer()> * init = nullptr)
    {
        static Fuzzer f{ (*init)() };
        return &f;
    }

    DeviceStateTracker * GetDeviceStateTracker() { return &mDeviceStateTracker; }
    ContextManager * GetContextManager() { return &mContextManager; }
    CallbackInterceptor * GetCallbackInterceptor() { return &mCallbackInterceptor; }
    StatsMonitor * GetStatsMonitor() { return &mStatsMonitor; }
    OutputLogger * GetOutputLogger() { return mOutputLogger; }
    Tuner * GetTuner() { return mTuner; }
    void SetOutputLogger(BasicInformation nodeInfo, fs::path outputDirectory);
    FuzzerPhase CurrentPhase() { return mCurrentPhase; }
    FuzzerMode CurrentMode() { return mCurrentMode; }
    std::string CurrentCommand() { return mCurrentCommand; }

    chip::app::ConcreteCommandPath CurrentAnalyzedPath() { return mCurrentAnalyzedPath; }
    NodeId CurrentDestination() { return mTarget; }

private:
    // Fuzzing<command>Command must be friend classes as they are the only allowed to instantiate the Fuzzer class.
    friend class ::FuzzingCommand;
    friend class ::FuzzingStartCommand;
    friend class ::FuzzingReplicateCommand;
    friend class ::FuzzingTuneCommand;

    // Fuzzer state data
    NodeId mTarget;
    size_t mTests;
    size_t mTestId = 0;
    std::string mCurrentCommand;
    FuzzerPhase mCurrentPhase = FuzzerPhase::INITIALIZATION;
    FuzzerMode mCurrentMode;
    chip::app::ConcreteCommandPath mCurrentAnalyzedPath;
    // std::vector<CommandHistoryEntry> mCommandHistory;
    const std::chrono::steady_clock::time_point mStartTime;

    // Components
    DeviceStateTracker mDeviceStateTracker;
    StatsMonitor mStatsMonitor;
    CallbackInterceptor mCallbackInterceptor;
    ContextManager mContextManager;
    OutputLogger * mOutputLogger = nullptr;
    Tuner * mTuner;

    Fuzzer(NodeId dst, size_t tests, FuzzerMode mode = FuzzerMode::TESTING) :
        mTarget(dst), mTests(tests), mCurrentMode(mode), mStartTime(std::chrono::steady_clock::now()),
        mStatsMonitor(mStartTime, mTarget) {};
    // Used only in tuning
    Fuzzer(NodeId dst, uint16_t minWaiting, double shrinkFactor, uint16_t shrinkCommandsInterval, double growthFactor,
           uint16_t growthCommandsInterval) :
        mTarget(dst), mTests(10000), mCurrentMode(FuzzerMode::TUNING), mStartTime(std::chrono::steady_clock::now()),
        mStatsMonitor(mStartTime, mTarget)
    {
        mTuner = new Tuner(minWaiting, shrinkFactor, shrinkCommandsInterval, growthFactor, growthCommandsInterval);
    };

    Fuzzer(const Fuzzer &)                 = delete;
    Fuzzer(Fuzzer &&) noexcept             = delete;
    Fuzzer & operator=(const Fuzzer &)     = delete;
    Fuzzer & operator=(Fuzzer &&) noexcept = delete;

    static void Initialize(NodeId dst, size_t tests, FuzzerMode mode = FuzzerMode::TESTING)
    {
        std::function<Fuzzer()> init = [&]() { return Fuzzer(dst, tests, mode); };
        GetInstance(&init);
    }

    // Used only in tuning
    static void Initialize(NodeId dst, uint16_t minWaiting, double shrinkFactor, uint16_t shrinkCommandsInterval,
                           double growthFactor, uint16_t growthCommandsInterval)
    {
        std::function<Fuzzer()> init = [&]() {
            return Fuzzer(dst, minWaiting, shrinkFactor, shrinkCommandsInterval, growthFactor, growthCommandsInterval);
        };
        GetInstance(&init);
    }

    void GoToNextPhase()
    {
        VerifyOrReturn(mCurrentPhase != FuzzerPhase::TESTING);
        mCurrentPhase = static_cast<FuzzerPhase>((static_cast<uint8_t>(mCurrentPhase) + 1));
    }
};
} // namespace fuzzing
} // namespace chip
