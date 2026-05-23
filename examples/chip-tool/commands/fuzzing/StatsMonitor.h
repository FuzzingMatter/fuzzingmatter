#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <app/ConcreteCommandPath.h>
namespace chip {
namespace fuzzing {

// TODO: This component should collect stats on the fuzzing process, such as the number of commands sent, the number of
// commands that timed out, the number of successes and failures, etc. We will discuss the exact requirements in the
// future.
class StatsMonitor
{
public:
    StatsMonitor(const std::chrono::steady_clock::time_point & startTime, const NodeId & dst) :
        mStartTime(startTime), mDestination(dst)
    {}

    const std::chrono::steady_clock::time_point & GetStartTime() { return mStartTime; }

    CHIP_ERROR AddObservation(DeviceStateTracker && dsTracker, types::FuzzerObservation & observation);

    void IncrementSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path);
    void ResetSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path);
    bool HasExceededSubscriptionTimeoutsLimit(const chip::app::ConcreteCommandPath & path)
    {
        return mSubscriptionTimeouts[path] >= kMaxSubscriptionTimeouts;
    }

    void TrackSkipped() { mSkippedTests++; }
    void TrackOrphanReport() { mOrphanReports++; }
    void TrackStatsFromContext(const FuzzerContext & context);
    CHIP_ERROR SaveData();

private:
    // A test is skipped when the generated testcase input could not be translated into a command packet correctly.
    uint64_t mSkippedTests = 0;

    // A report is orphan when it is caused by a previous command but it comes out-of-sequence in the current context.
    uint64_t mOrphanReports = 0;

    /**
     * Tracks the number of times a command did not send any subscription report back, timing out.
     * After a command timed out three times IN A ROW, the fuzzer will not wait anymore for the subscription report to come.
     */
    std::unordered_map<chip::app::ConcreteCommandPath, uint16_t, types::MapKeyHasher> mSubscriptionTimeouts;
    std::unordered_map<types::FuzzerObservation, uint64_t, types::MapKeyHasher, types::MapKeyEqualizer> mObservationCounters;
    std::unordered_map<chip::app::ConcreteCommandPath, uint64_t, types::MapKeyHasher> mTestcasesPerCommand;
    std::unordered_map<chip::app::ConcreteCommandPath, std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher>,
                       types::MapKeyHasher>
        mErrorMapPerCommand;
    std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher> mErrorCounters;
    std::vector<types::ExecutionStats> mCommandExecutionStats;

    const std::chrono::steady_clock::time_point & mStartTime;
    const NodeId & mDestination;
    const uint64_t kMaxSubscriptionTimeouts = 15U;
};
} // namespace fuzzing
} // namespace chip
