#include "OutputLogger.h"
#include "Utils.h"
#include "Visitors.h"
#include "tlv/DecodedTLVElement.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <fstream>
#include <yaml-cpp/yaml.h>

namespace {
CHIP_ERROR DumpContainer(const fuzz::ContainerType & container, YAML::Emitter & emitter)
{
    emitter << YAML::Key << "value" << YAML::BeginSeq;
    for (const auto & element : container)
    {
        std::string attributeType = fuzz::Visitors::AttributeTypeAsString(element->content);
        emitter << YAML::BeginMap;
        emitter << YAML::Key << "type" << YAML::Value << attributeType;
        if (attributeType == "container")
        {
            VerifyOrReturnError(std::holds_alternative<fuzz::ContainerType>(element->content), CHIP_ERROR_INTERNAL);
            ReturnErrorOnFailure(DumpContainer(std::get<fuzz::ContainerType>(element->content), emitter));
        }
        else
            emitter << YAML::Key << "value" << YAML::Value << fuzz::Visitors::AttributeValueAsString(element->content);

        emitter << YAML::EndMap;
    }
    emitter << YAML::EndSeq;
    return CHIP_NO_ERROR;
}
} // namespace

/*
    This method logs the state of the device before the command is executed, the command itself, and the status code returned by the
   device. The structure should be the following:

    .../chip-fuzzer/<vendorName>_<vendorId>_<hwVersion>_<swVersion>/
    ├── grammar/
    │   └── files...
    ├── results/
    │   ├── <endpoint>/
    │   │   ├── <cluster>/
    │   │   │   ├── <command>/
    │   │   │   │   └── <statusCode>_<changedAttr>_...<changedAttrs>.yaml
    │   │   │   ├── <command>/
    │   │   │   │   └── <statusCode>_<changedAttr>_...<changedAttrs>.yaml
    │   │   │   │   └── ...
    │   │   │   └── .../
    │   │   ├── <clusters...>/
    │   │   │   └── .../
    │   │   ├── .../
    │   ├── <endpoints...>/
    │   │   └── .../
    │   └── .../

    The .yaml files should have the following keys:

    - "state" is a dump of the state before the command issued;
    - "command" is the command string executed.
*/

// NOTE! The LogObservation method should be called BEFORE the DeviceStateTracker modifies the tracked state after the execution of
// the command.
CHIP_ERROR fuzz::OutputLogger::LogObservation(DeviceStateTracker && dsTracker, std::chrono::steady_clock::time_point timestamp,
                                              std::string cmd, chip::app::ConcreteCommandPath cmdPath, CHIP_ERROR statusCode,
                                              std::shared_ptr<types::AnyType> responseData,
                                              std::vector<types::AttributePathMap> * reportedData)
{
    YAML::Emitter emitter;
    auto observedAfterMs = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp - mStartTime).count();
    emitter << YAML::BeginMap;
    emitter << YAML::Key << "observedAfterMs" << YAML::Value << observedAfterMs;

    emitter << YAML::Key << "state" << YAML::Value << YAML::BeginMap;
    emitter << YAML::Key << mNodeId << YAML::Value << YAML::BeginMap;

    const auto * endpoints = dsTracker.List(mNodeId);
    VerifyOrDie(endpoints != nullptr);
    // A local std::map is used because device state is tracked inside an unordered map and we need to dump the keys in ascending
    // order.
    emitter << YAML::Key << "endpoints" << YAML::Value << YAML::BeginMap;
    for (auto & [endpointId, endpointState] : std::map<EndpointId, EndpointState>(endpoints->begin(), endpoints->end()))
    {
        emitter << YAML::Key << endpointId << YAML::Value << YAML::BeginMap;
        emitter << YAML::Key << "deviceTypes" << YAML::Value << YAML::BeginSeq;

        std::set<DeviceTypeId> deviceTypeIds;
        for (auto & deviceType : endpointState.deviceTypes)
        {
            if (deviceTypeIds.find(deviceType.id) == deviceTypeIds.end())
            {
                deviceTypeIds.emplace(deviceType.id);
                emitter << YAML::BeginMap << YAML::Key << "id" << YAML::Value << deviceType.id;
                emitter << YAML::Key << "revision" << YAML::Value << deviceType.revision << YAML::EndMap;
            }
        }
        // end deviceTypes sequence
        emitter << YAML::EndSeq;

        const auto * clusters = dsTracker.List(mNodeId, endpointId);
        VerifyOrDie(clusters != nullptr);

        emitter << YAML::Key << "clusters" << YAML::Value << YAML::BeginMap;
        for (auto & [clusterId, clusterState] : std::map<ClusterId, ClusterState>(clusters->begin(), clusters->end()))
        {
            emitter << YAML::Key << clusterId << YAML::Value << YAML::BeginMap;
            emitter << YAML::Key << "revision" << YAML::Value << clusterState.clusterRevision;
            const auto * attributes = dsTracker.List(mNodeId, endpointId, clusterId);
            VerifyOrDie(attributes != nullptr);

            emitter << YAML::Key << "attributes" << YAML::Value << YAML::BeginMap;
            for (auto & [attributeId, attributeState] :
                 std::map<AttributeId, AttributeState>(attributes->begin(), attributes->end()))
            {
                // Do not print global attributes
                if (attributeId >= 0xFFF0)
                    continue;
                if (!attributeState.IsReadable())
                {
                    emitter << YAML::Key << attributeId << YAML::Value << "unreadable";
                    continue;
                }
                const types::AnyType & attributeValue = attributeState.ReadCurrent();
                emitter << YAML::Key << attributeId << YAML::Value << YAML::BeginMap;
                std::string attributeType = Visitors::AttributeTypeAsString(attributeValue);
                emitter << YAML::Key << "type" << YAML::Value << attributeType;
                if (attributeType == "container")
                {
                    VerifyOrReturnError(std::holds_alternative<ContainerType>(attributeValue), CHIP_ERROR_INTERNAL);
                    ReturnErrorOnFailure(DumpContainer(std::get<ContainerType>(attributeValue), emitter));
                }
                else
                {
                    emitter << YAML::Key << "value" << YAML::Value << Visitors::AttributeValueAsString(attributeValue);
                }
                // TODO: We should manage nullable/optional attributes (we may add a nullable: true/false or optional:
                // TODO: true/false field)
                // end attribute map
                emitter << YAML::EndMap;
            }
            // end attributes map
            emitter << YAML::EndMap;
            // end cluster map
            emitter << YAML::EndMap;
        }
        // end clusters map
        emitter << YAML::EndMap;
        // end endpoint map
        emitter << YAML::EndMap;
    }

    // end endpoints map
    emitter << YAML::EndMap;
    // end <nodeId> map
    emitter << YAML::EndMap;
    // end state map
    emitter << YAML::EndMap;

    emitter << YAML::Key << "command" << YAML::Value << cmd;
    if (responseData)
    {
        emitter << YAML::Key << "response" << YAML::Value << YAML::BeginMap;
        if (std::holds_alternative<ContainerType>(*responseData))
        {
            ReturnErrorOnFailure(DumpContainer(std::get<ContainerType>(*responseData), emitter));
        }
        else
        {
            emitter << YAML::Key << "value" << YAML::Value << Visitors::AttributeValueAsString(*responseData);
        }
        emitter << YAML::EndMap;
    }

    if (reportedData && reportedData->size())
    {
        emitter << YAML::Key << "reported" << YAML::Value << YAML::BeginSeq;
        for (auto & report : *reportedData)
        {
            emitter << YAML::BeginMap;
            emitter << YAML::Key << "data" << YAML::Value << YAML::BeginSeq;
            for (auto & [attrPath, attrValue] : report)
            {
                emitter << YAML::BeginMap;
                emitter << YAML::Key << "endpoint" << YAML::Hex << attrPath.mEndpointId;
                emitter << YAML::Key << "cluster" << YAML::Hex << attrPath.mClusterId;
                emitter << YAML::Key << "attribute" << YAML::Hex << attrPath.mAttributeId;
                emitter << YAML::Key << "type" << YAML::Value << Visitors::AttributeTypeAsString(attrValue);
                if (Visitors::AttributeTypeAsString(attrValue) == "container")
                {
                    VerifyOrReturnError(std::holds_alternative<ContainerType>(attrValue), CHIP_ERROR_INTERNAL);
                    ReturnErrorOnFailure(DumpContainer(std::get<ContainerType>(attrValue), emitter));
                }
                else
                {
                    emitter << YAML::Key << "value" << YAML::Value << Visitors::AttributeValueAsString(attrValue);
                }
                // end attribute map
                emitter << YAML::EndMap;
            }
            // end data sequence
            emitter << YAML::EndSeq;
            // end report map
            emitter << YAML::EndMap;
        }
        // end reported sequence
        emitter << YAML::EndSeq;
    }
    // end root map
    emitter << YAML::EndMap;

    // Generate folder structure with the syntax
    // `<vendorName>_<vendorId>_<productId>_<hwVersion>_<swVersion>/<endpointId>/<clusterId>/<commandId>/...`
    // `└──────────────────────device info─────────────────────────┘└─────────data model path──────────┘`
    std::ostringstream pDataModel;
    pDataModel << std::hex << mNodeId << "/" << cmdPath.mEndpointId << "/" << cmdPath.mClusterId << "/" << cmdPath.mCommandId;
    fs::path pObservationOutput(mpOutputDirectory / pDataModel.str());

    if (!fs::exists(pObservationOutput))
    {
        fs::create_directories(pObservationOutput);
    }

    std::ostringstream fileName;
    fileName << observedAfterMs << "_" << std::hex << statusCode.AsInteger() << ".yaml";

    std::ofstream file(pObservationOutput / fileName.str(), std::ios::ate);
    file << emitter.c_str();
    file.close();

    return CHIP_NO_ERROR;
}

CHIP_ERROR
fuzz::OutputLogger::LogStatistics(
    std::unordered_map<chip::app::ConcreteCommandPath, uint64_t, types::MapKeyHasher> * testcasesPerCommand,
    std::unordered_map<chip::app::ConcreteCommandPath, std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher>,
                       types::MapKeyHasher> * errorMapPerCommand,
    std::unordered_map<CHIP_ERROR, uint64_t, types::MapKeyHasher> * errorCounters,
    std::vector<types::ExecutionStats> * commandExecutionStats, uint64_t * skipped, uint64_t * orphans)
{
    VerifyOrReturnError(testcasesPerCommand && errorMapPerCommand && errorCounters && commandExecutionStats && skipped && orphans,
                        CHIP_ERROR_INVALID_ARGUMENT);

    YAML::Emitter emitter;
    emitter << YAML::BeginMap;
    emitter << YAML::Key << "issued" << YAML::Value
            << std::accumulate(testcasesPerCommand->begin(), testcasesPerCommand->end(), uint64_t{ 0 },
                               [](uint64_t acc, auto & el) { return acc + el.second; });
    emitter << YAML::Key << "succeeded" << YAML::Value
            << std::accumulate(errorMapPerCommand->begin(), errorMapPerCommand->end(), uint64_t{ 0 }, [](uint64_t acc, auto & pair) {
                   return acc + std::accumulate(pair.second.begin(), pair.second.end(), uint64_t{ 0 }, [](uint64_t errorAcc, auto & errorPair) {
                              return errorPair.first == CHIP_NO_ERROR ? errorAcc + errorPair.second : errorAcc;
                          });
               });
    emitter << YAML::Key << "failed" << YAML::Value
            << std::accumulate(errorMapPerCommand->begin(), errorMapPerCommand->end(), uint64_t{ 0 }, [](uint64_t acc, auto & pair) {
                   return acc + std::accumulate(pair.second.begin(), pair.second.end(), uint64_t{ 0 }, [](uint64_t errorAcc, auto & errorPair) {
                              return errorPair.first != CHIP_NO_ERROR ? errorAcc + errorPair.second : errorAcc;
                          });
               });
    emitter << YAML::Key << "timeouts" << YAML::Value
            << std::accumulate(errorMapPerCommand->begin(), errorMapPerCommand->end(), uint64_t{ 0 }, [](uint64_t acc, auto & pair) {
                   return acc + std::accumulate(pair.second.begin(), pair.second.end(), uint64_t{ 0 }, [](uint64_t errorAcc, auto & errorPair) {
                              return errorPair.first == CHIP_ERROR_TIMEOUT ? errorAcc + errorPair.second : errorAcc;
                          });
               });
    emitter << YAML::Key << "skipped" << YAML::Value << *skipped;
    emitter << YAML::Key << "orphanReports" << YAML::Value << *orphans;
    emitter << YAML::Key << "testcasesPerCommand" << YAML::Value << YAML::BeginSeq;
    for (auto & [path, count] : *testcasesPerCommand)
    {
        bool generatesReport = !fuzz::Fuzzer::GetInstance()->GetStatsMonitor()->HasExceededSubscriptionTimeoutsLimit(path);
        emitter << YAML::BeginMap;
        emitter << YAML::Key << "path" << YAML::Value << YAML::Hex
                << "(" + std::to_string(path.mEndpointId) + "," + std::to_string(path.mClusterId) + "," +
                std::to_string(path.mCommandId) + ")"
                << YAML::Dec;
        emitter << YAML::Key << "count" << YAML::Value << count;
        emitter << YAML::Key << "generatesReport" << YAML::Value << generatesReport;
        emitter << YAML::EndMap;
    }
    emitter << YAML::EndSeq;
    emitter << YAML::Key << "errorsPerCommand" << YAML::Value << YAML::BeginSeq;
    for (auto & [path, errors] : *errorMapPerCommand)
    {
        emitter << YAML::BeginMap;
        emitter << YAML::Key << "path" << YAML::Value << YAML::Hex
                << "(" + std::to_string(path.mEndpointId) + "," + std::to_string(path.mClusterId) + "," +
                std::to_string(path.mCommandId) + ")"
                << YAML::Dec;
        emitter << YAML::Key << "errors" << YAML::Value << YAML::BeginMap;
        for (auto & [error, count] : errors)
        {
            emitter << YAML::Key << YAML::Hex << error.AsInteger() << YAML::Value << YAML::Dec << count;
        }
        emitter << YAML::EndMap;
        emitter << YAML::EndMap;
    }
    emitter << YAML::EndSeq;
    emitter << YAML::Key << "errorCounters" << YAML::Value << YAML::BeginMap;
    for (auto & [error, count] : *errorCounters)
    {
        emitter << YAML::Key << YAML::Hex << error.AsInteger() << YAML::Value << YAML::Dec << count;
    }
    emitter << YAML::EndMap;

    using time_point = std::chrono::time_point<std::chrono::steady_clock>;
    // The default-constructed time_point has an internal integer value of 0
    auto isInvalidTime = [](time_point t) { return t == time_point{}; };
    auto getInterval   = [isInvalidTime](time_point start, time_point end) -> int64_t {
        if (isInvalidTime(start) || isInvalidTime(end))
            return 0;
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    };

    std::chrono::microseconds totalExecutionTime(0);

    emitter << YAML::Key << "commandExecutionStats" << YAML::Value << YAML::BeginSeq;
    for (auto & stats : *commandExecutionStats)
    {
        // If this is invalid, the command was skipped
        if (isInvalidTime(stats.issTime))
            continue;
        auto RTT = getInterval(stats.txTime, stats.rxTime);
        if (RTT == 0)
        {
            RTT = getInterval(stats.schTime, stats.rxTime);
        }
        auto repRxTime  = getInterval(stats.waitForRepRxTime, stats.repRxTime);
        auto txOverhead = getInterval(stats.issTime, stats.txTime);
        if (txOverhead == 0)
        {
            txOverhead = getInterval(stats.issTime, stats.schTime);
        }
        // Time spent for processing command response.
        auto rxOverhead = getInterval(stats.rxTime, stats.waitForRepRxTime);
        if (rxOverhead == 0)
        {
            rxOverhead = getInterval(stats.rxTime, stats.finishTime);
        }
        // Time spent for processing the reports and closing the context. If this is 0, rxOverhead > 0.
        auto repRxOverhead = getInterval(stats.repRxTime, stats.finishTime);
        auto total         = getInterval(stats.issTime, stats.finishTime);
        emitter << YAML::BeginMap;
        emitter << YAML::Key << "RTT" << YAML::Value << (std::to_string(RTT) + "μs");
        emitter << YAML::Key << "repRxTime" << YAML::Value << (std::to_string(repRxTime) + "μs");
        emitter << YAML::Key << "overhead" << YAML::Value << std::to_string(txOverhead + rxOverhead + repRxOverhead) + "μs";
        emitter << YAML::Key << "total" << YAML::Value << std::to_string(total) + "μs";

        totalExecutionTime += std::chrono::microseconds(total);
        emitter << YAML::EndMap;
    }
    emitter << YAML::EndSeq;

    emitter << YAML::Key << "averageExecutionTime" << YAML::Value
            << std::to_string(totalExecutionTime.count() / static_cast<decltype(totalExecutionTime)::rep>(commandExecutionStats->size())) + "μs";
    emitter << YAML::Key << "averageCommandsPerSecond" << YAML::Value
            << std::to_string(static_cast<double>(commandExecutionStats->size()) /
                              std::chrono::duration_cast<std::chrono::duration<double>>(totalExecutionTime).count());
    emitter << YAML::EndMap;

    fs::path pStatisticsOutput(mpOutputDirectory / "statistics.yaml");
    std::ofstream file(pStatisticsOutput, std::ios::trunc);
    file << emitter.c_str();
    file.close();
    return CHIP_NO_ERROR;
}
