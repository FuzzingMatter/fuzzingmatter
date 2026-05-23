#pragma once
#include "ForwardDeclarations.h"
#include "Fuzzer.h"

namespace chip {
namespace fuzzing {
class OutputLogger
{
public:
    OutputLogger(fuzz::BasicInformation nodeInfo, NodeId id, fs::path apOutputDirectory,
                 const std::chrono::steady_clock::time_point & startTime) :
        mNodeInfo(nodeInfo), mNodeId(id), mpOutputDirectory(apOutputDirectory), mStartTime(startTime)
    {}

    CHIP_ERROR LogObservation(DeviceStateTracker && dsTracker, std::chrono::steady_clock::time_point timestamp, std::string cmd,
                              chip::app::ConcreteCommandPath cmdPath, CHIP_ERROR statusCode,
                              std::shared_ptr<types::AnyType> responseData, std::vector<types::AttributePathMap> * reportedData);
    CHIP_ERROR
    LogStatistics(std::unordered_map<chip::app::ConcreteCommandPath, uint64_t, types::MapKeyHasher> * testcasesPerCommand,
                  std::unordered_map<chip::app::ConcreteCommandPath, std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher>,
                                     types::MapKeyHasher> * errorMapPerCommand,
                  std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher> * errorCounters,
                  std::vector<types::ExecutionStats> * commandExecutionStats, uint64_t * skipped, uint64_t * orphans);

private:
    fuzz::BasicInformation mNodeInfo;
    const NodeId mNodeId;
    const fs::path mpOutputDirectory;
    const std::chrono::steady_clock::time_point & mStartTime;
};
} // namespace fuzzing
} // namespace chip
