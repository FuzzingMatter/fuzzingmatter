#include "FuzzingCommands.h"
#include "DeviceStateTracker.h"
#include "OutputLogger.h"
#include "Utils.h"
#include "Visitors.h"
#include "editline.h"
#include "generation/InputGenerator.h"
#include "tlv/DecodedTLVElement.h"
#include <algorithm>
#include <app/MessageDef/StatusIB.h>
#include <atomic>
#include <csignal>
#include <cstring>
#include <future>
#include <numeric>
#include <random>
#include <regex>
#include <string>
#include <thread>
namespace {
inline std::string GetRetrieveEndpointsCommand(chip::NodeId node)
{
    std::string kCommand("descriptor read parts-list ");
    kCommand.append(std::to_string(node)).append(" 0");
    return kCommand;
}; // returns endpoints of the node
inline std::string GetRetrieveDeviceTypeCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    std::string kCommand("descriptor read device-type-list "); // returns device type for each endpoint of the node
    kCommand.append(std::to_string(node)).append(" ").append(std::to_string(endpoint));
    return kCommand;
}; // returns device type of the endpoint
inline std::string GetRetrieveServerClustersCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    std::string kCommand("descriptor read server-list ");
    kCommand.append(std::to_string(node)).append(" ").append(std::to_string(endpoint));
    return kCommand;
}; // returns clusters of all endpoints
inline std::string GetReadAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any read-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint));
    return kCommand;
}; // reads all attributes
inline std::string GetSubscribeAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any subscribe-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF")
        .append(" 0")
        .append(" -1 ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint))
        .append(" --keepSubscriptions true");
    return kCommand;
}; // subscribes to all attributes

std::atomic<bool> gStopRequested = false;

void RequestFuzzerStop(int signal)
{
    ChipLogProgress(chipToolFuzzing, "Received signal %d. Stopping the fuzzer...", signal);
    gStopRequested = true;
}
} // namespace

template <typename T>
void FuzzingCommand::ExecuteCommand(const char * command, CHIP_ERROR * status, T * responseOutput,
                                    std::vector<types::AttributePathMap> * reportOutput)
{
    auto fuzzer             = fuzz::Fuzzer::GetInstance();
    fuzzer->mCurrentCommand = command;
    std::istringstream commandStream(command);
    {
        std::string trash;
        commandStream >> trash >> trash >> fuzzer->mCurrentAnalyzedPath.mClusterId >> fuzzer->mCurrentAnalyzedPath.mCommandId >>
            trash >> trash >> fuzzer->mCurrentAnalyzedPath.mEndpointId;
    }

    bool needsLog = fuzzer->CurrentPhase() == fuzz::FuzzerPhase::TESTING;

    *status = mHandler->RunFuzzing(command);

    if (CHIP_ERROR_INVALID_ARGUMENT == *status)
    {
        ChipLogError(chipToolFuzzing, "Could not parse command string correctly. Skipping test case.");
        fuzzer->GetStatsMonitor()->TrackSkipped();
        return;
    }

    auto contextManager = fuzzer->GetContextManager();
    if (CHIP_ERROR_TIMEOUT == *status)
    {
        contextManager->OnResponseTimeout();
    }
    else if (CHIP_NO_ERROR == *status && CHIP_NO_ERROR != contextManager->WaitForSubscriptionReport(reportOutput))
    {
        ChipLogError(chipToolFuzzing, "No report received for command '%s'.", command);
    }
    else if (responseOutput)
    {
        VerifyOrDieWithSave(CHIP_NO_ERROR == contextManager->GetResponseData(responseOutput));
    }

    VerifyOrDieWithSave(CHIP_NO_ERROR == contextManager->Close(needsLog));
}

template void FuzzingCommand::ExecuteCommand(const char * command, CHIP_ERROR * status, types::AnyType * responseOutput,
                                             std::vector<types::AttributePathMap> * reportOutput);
template void FuzzingCommand::ExecuteCommand(const char * command, CHIP_ERROR * status, types::AttributePathMap * responseOutput,
                                             std::vector<types::AttributePathMap> * reportOutput);

bool FuzzingCommand::TestTCPServerSupport(chip::NodeId id)
{
    auto fuzzer    = fuzz::Fuzzer::GetInstance();
    auto dsTracker = fuzzer->GetDeviceStateTracker();

    CHIP_ERROR err = CHIP_NO_ERROR;
    VerifyOrDieWithSave(dsTracker->List(id) && !!(dsTracker->List(id)->size()));
    for (auto & [endpointId, _] : *dsTracker->List(id))
    {
        VerifyOrDieWithSave(dsTracker->List(id, endpointId) && !!(dsTracker->List(id, endpointId)->size()));
        for (auto & [clusterId, _] : *dsTracker->List(id, endpointId))
        {
            auto commandList = dsTracker->ReadAttribute(id, endpointId, clusterId,
                                                        chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id);
            if (!std::holds_alternative<fuzz::ContainerType>(commandList) || !std::get<fuzz::ContainerType>(commandList).size())
                continue;

            auto firstCommand      = std::get<fuzz::ContainerType>(commandList).front();
            auto commandId         = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(firstCommand);
            std::string commandStr = "any command-by-id " + std::to_string(clusterId) + " " + std::to_string(commandId) + " {} " +
                std::to_string(id) + " " + std::to_string(endpointId) + " --allow-large-payload true";

            ExecuteCommand(commandStr.c_str(), &err);
            return err != CHIP_ERROR_INTERNAL;
        }
    }
    return false;
}

CHIP_ERROR AcquireBasicInformation(FuzzingCommand * handler, chip::NodeId dst)
{
    CHIP_ERROR status          = CHIP_NO_ERROR;
    std::ostringstream command = std::ostringstream() << "basicinformation read data-model-revision " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-name " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-id " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read product-id " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read hardware-version " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read software-version " << dst << " 0";
    handler->ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    return CHIP_NO_ERROR;
}

/**
 * Acquires the remote data model for a given NodeId.
 *
 * This method is responsible for acquiring the remote data model for a specific NodeId. It retrieves
 * the endpoints, device types, server clusters, and cluster attributes for the given NodeId. It also
 * subscribes to all cluster attributes for each endpoint and cluster. If any of the commands
 * fail to execute successfully, an error code is returned.
 *
 * @param id The NodeId for which to acquire the remote data model.
 * @return CHIP_NO_ERROR on success, or an error code indicating the reason for failure.
 */
CHIP_ERROR
AcquireRemoteDataModel(FuzzingCommand * handler, chip::NodeId dst)
{
    // Access to the device state manager is required to add the new node and list the endpoints.
    auto fuzzer                            = fuzz::Fuzzer::GetInstance();
    fuzz::DeviceStateTracker * deviceState = fuzzer->GetDeviceStateTracker();
    CHIP_ERROR status                      = CHIP_NO_ERROR;
    deviceState->Add(dst);

    /**
     * Steps:
     * 1) get the endpoints of the node;
     * 2) for each endpoint, get the device type and server clusters (those who respond to commands);
     * 3) for each cluster, read all attributes and subscribe to them.
     *
     * The command response callbacks will parse the response and update the device state accordingly.
     */
    std::string retrieveEndpointsCommand = GetRetrieveEndpointsCommand(dst);

    handler->ExecuteCommand(retrieveEndpointsCommand.c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    VerifyOrReturnError(deviceState->List(dst) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    for (auto & [endpointId, _] : *deviceState->List(dst))
    {
        std::string retrieveDeviceTypeCommand     = GetRetrieveDeviceTypeCommand(dst, endpointId);
        std::string retrieveServerClustersCommand = GetRetrieveServerClustersCommand(dst, endpointId);
        handler->ExecuteCommand(retrieveDeviceTypeCommand.c_str(), &status);
        VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        handler->ExecuteCommand(retrieveServerClustersCommand.c_str(), &status);
        VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        VerifyOrReturnError(deviceState->List(dst, endpointId) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        for (auto & [clusterId, _] : *deviceState->List(dst, endpointId))
        {
            std::string readAllClusterAttributesCommand = GetReadAllClusterAttributesCommand(dst, endpointId, clusterId);

            // Even if the subscribe command returns the initial value of the attributes, the device state tracker would not have
            // any information about the attribute, therefore it is necessary to read the attributes first.
            // TODO: Can this be done in a single command?
            handler->ExecuteCommand(readAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        }
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR SubscribeAttributes(FuzzingCommand * handler, chip::NodeId dst)
{
    auto deviceState  = fuzz::Fuzzer::GetInstance()->GetDeviceStateTracker();
    CHIP_ERROR status = CHIP_NO_ERROR;

    for (auto & endpoint : *deviceState->List(dst))
    {
        for (auto & cluster : *deviceState->List(dst, endpoint.first))
        {
            std::string subscribeAllClusterAttributesCommand =
                GetSubscribeAllClusterAttributesCommand(dst, endpoint.first, cluster.first);

            handler->ExecuteCommand(subscribeAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            VerifyOrReturnError(deviceState->List(dst, endpoint.first, cluster.first) != nullptr,
                                CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        }
    }
    return CHIP_NO_ERROR;
}
CHIP_ERROR FuzzingCommand::InitializeFuzzer(chip::NodeId dst, uint64_t tests, fuzz::FuzzerMode mode)
{
    CHIP_ERROR status = CHIP_NO_ERROR;
    fuzz::Fuzzer::Initialize(dst, tests, mode);

    VerifyOrReturnError(fuzz::Fuzzer::GetInstance() != nullptr, CHIP_FUZZER_ERROR_CORE_INITIALIZATION_FAILED);
    // Clean existing subscriptions from previous runs
    ExecuteCommand("subscriptions shutdown-all", &status);
    return status;
}

// Used only in tuning
CHIP_ERROR FuzzingCommand::InitializeFuzzer(chip::NodeId dst, uint16_t minWaiting, double shrinkFactor,
                                            uint16_t shrinkCommandsInterval, double growthFactor, uint16_t growthCommandsInterval)
{
    CHIP_ERROR status = CHIP_NO_ERROR;
    fuzz::Fuzzer::Initialize(dst, minWaiting, shrinkFactor, shrinkCommandsInterval, growthFactor, growthCommandsInterval);

    VerifyOrReturnError(fuzz::Fuzzer::GetInstance() != nullptr, CHIP_FUZZER_ERROR_CORE_INITIALIZATION_FAILED);
    // Clean existing subscriptions from previous runs
    ExecuteCommand("subscriptions shutdown-all", &status);
    return status;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    ReturnErrorOnFailure(InitializeFuzzer(mDestinationId, mTests));

    CHIP_ERROR status = CHIP_NO_ERROR;
    auto fuzzer       = fuzz::Fuzzer::GetInstance();
    auto dsTracker    = fuzzer->GetDeviceStateTracker();
    fuzzer->GetContextManager()->SetReportTimeout(std::chrono::milliseconds(mReportTimeout));

    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AcquireRemoteDataModel(this, mDestinationId));

    auto * endpointList = dsTracker->List(mDestinationId);
    VerifyOrReturnError(endpointList, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    LogErrorOnFailure(AcquireBasicInformation(this, mDestinationId));
    mDestinationSupportsTCPServer = TestTCPServerSupport(mDestinationId);
    ReturnErrorOnFailure(SubscribeAttributes(this, mDestinationId));

    const fuzz::BasicInformation * nodeInfo = dsTracker->GetNodeInformation(mDestinationId);
    fuzzer->SetOutputLogger(*nodeInfo, GetOutputDirectory());

    fs::path pGeneratedGrammarsDirectory = GetOutputDirectory() / nodeInfo->ToString() / "grammar";

    fuzz::generation::InputGenerator inputGenerator(nodeInfo, pGeneratedGrammarsDirectory.string());
    fs::path pTestcasesFile = GetOutputDirectory() / nodeInfo->ToString() / "tests.txt";
    inputGenerator.CreateGrammar(dsTracker, mDestinationId);
    inputGenerator.GenerateTestCases(pTestcasesFile, mTests);

    fuzzer->GoToNextPhase();

    // From here the fuzzer process can be aborted cleanly
    std::signal(SIGINT, RequestFuzzerStop);

    std::ifstream file(pTestcasesFile);
    std::string generatedArgs;
    uint64_t consecutiveTimeouts = 0;
    while (std::getline(file, generatedArgs) && !gStopRequested && consecutiveTimeouts <= fuzz::kMaxConsecutiveTimeouts)
    {
        std::string command = "any command-by-id ";
        /**
         * Strings generated by Grammarinator come with the form ENDPOINT CLUSTER COMMAND JSON.
         * To fit the generated content into a command, we must preprocess it to fit the syntax "any command-by-id CLUSTER
         * COMMAND JSON NODE ENDPOINT" as required by the chip-tool parser. Also, the JSON must be preprocessed to convert hex
         * values to decimal and to remove duplicate keys.
         */
        command += fuzz::generation::InputGenerator::ParseTestCase(mDestinationId, generatedArgs);
        ExecuteCommand(command.c_str(), &status);
        if (status == CHIP_ERROR_TIMEOUT)
            consecutiveTimeouts++;
        else
            consecutiveTimeouts = 0;
    }

    file.close();

    ChipLogProgress(chipToolFuzzing, "Fuzzing completed in %s. Dumping telemetry data...",
                    fuzz::GetElapsedTime(fuzzer->GetStatsMonitor()->GetStartTime()).c_str());

    LogErrorOnFailure(fuzzer->GetStatsMonitor()->SaveData());
    ChipLogProgress(chipToolFuzzing, "Cleaning up data allocated by the fuzzer...");

    LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};

CHIP_ERROR FuzzingReplicateCommand::RunCommand()
{
    std::vector<types::AttributePathMap> expectedSubscriptionOutput;
    types::AnyType expectedResponseOutput;
    chip::NodeId target;
    CHIP_ERROR status;

    fs::path pExperimentFile        = mExperimentFile;
    fs::path pExperimentFileAbsPath = GetOutputDirectory() / pExperimentFile;
    if (!fs::exists(pExperimentFileAbsPath))
    {
        ChipLogError(chipToolFuzzing, "Experiment file not found.");
        status = CHIP_ERROR_INVALID_ARGUMENT;
        SetCommandExitStatus(status);
        return status;
    }

    YAML::Node root = YAML::LoadFile(pExperimentFileAbsPath.string());

    // Tokenizing the experiment file path over the characters `/_.` returns a 12 + N tokens vector, where the first 5 tokens are
    // the target information, the next 5 are the token "results" and the ids composing the full data model path (node, endpoint,
    // cluster, command), the 11th is the status code, the next N are the N reported attributes and the last one is the file
    // extension "yaml".
    std::regex re("[/_.]"); // Matches both '/', '_' or '.'
    std::string regexInput = pExperimentFile.string();
    std::sregex_token_iterator begin(regexInput.begin(), regexInput.end(), re, -1);
    std::sregex_token_iterator end;
    std::vector<std::string> tokens(begin, end);

    target = static_cast<chip::NodeId>(std::stoull(tokens[6], nullptr, 16));

    ChipLogProgress(chipToolFuzzing, "Verifying experiment:");
    ChipLogProgress(chipToolFuzzing,
                    "Vendor name: %s, Vendor ID: 0x%04X, Product ID: 0x%04X, Hardware version: 0x%04X, "
                    "Software version: 0x%08X",
                    tokens[0].c_str(), static_cast<unsigned>(std::stoul(tokens[1], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[2], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[3], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[4], nullptr, 16)));
    ChipLogProgress(chipToolFuzzing,
                    "Node ID: 0x" ChipLogFormatX64 ", Data model command: (0x%04X, 0x%08X, 0x%08X), "
                    "Status code: 0x%08X",
                    ChipLogValueX64(target), static_cast<unsigned>(std::stoul(tokens[7], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[8], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[9], nullptr, 16)),
                    static_cast<unsigned>(std::stoul(tokens[11], nullptr, 16)));

    if (!root["response"])
    {
        ChipLogProgress(chipToolFuzzing, "Response data: none");
    }
    else
    {
        ChipLogProgress(chipToolFuzzing, "Response data:");
        int fieldIdx = 0;
        for (const auto & field : root["response"]["value"])
        {
            ChipLogProgress(chipToolFuzzing, "\t[%d] Type: %s", ++fieldIdx, field["type"].as<std::string>().c_str());
        }
    }

    if (!root["reported"])
    {
        ChipLogProgress(chipToolFuzzing, "Reported attributes: none");
    }
    else
    {
        ChipLogProgress(chipToolFuzzing, "Reported attributes:");
        int reportIdx = 0;
        for (const auto & report : root["reported"])
        {
            ChipLogProgress(chipToolFuzzing, "\tReport %d:", ++reportIdx);
            int attrIdx = 0;
            for (const auto & attribute : report["data"])
            {
                ChipLogProgress(chipToolFuzzing,
                                "\t\t[%d] Endpoint: 0x%04" PRIX16 ", Cluster: 0x%08" PRIX32 ", Attribute: 0x%08" PRIX32
                                ", Type: %s",
                                ++attrIdx, attribute["endpoint"].as<chip::EndpointId>(), attribute["cluster"].as<chip::ClusterId>(),
                                attribute["attribute"].as<chip::AttributeId>(), attribute["type"].as<std::string>().c_str());
            }
        }
    }

    ReturnErrorOnFailure(InitializeFuzzer(target, 0, fuzz::FuzzerMode::REPLICATION));

    auto fuzzer    = fuzz::Fuzzer::GetInstance();
    auto dsTracker = fuzzer->GetDeviceStateTracker();

    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AcquireRemoteDataModel(this, target));
    auto * endpointList = dsTracker->List(target);
    VerifyOrReturnError(endpointList, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    auto endpointId = static_cast<chip::EndpointId>(std::stoul(tokens[7], nullptr, 16));
    auto clusterId  = static_cast<chip::ClusterId>(std::stoul(tokens[8], nullptr, 16));
    status          = dsTracker->Load(root, true, this, true, chip::app::ConcreteClusterPath(endpointId, clusterId));
    if (status != CHIP_NO_ERROR)
    {
        // This error will be thrown less and less when we will implement the device's state machine, because we could explore the
        // transitions between various configurations and therefore we could infer which command(s) can write an attribute in an
        // indirect way, i.e. bring the device to a particular state unreachable with a WriteAttributeCommand.
        ChipLogError(chipToolFuzzing, "Replication failed: the remote device's state could not be synchronized.");

        LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
        SetCommandExitStatus(status);
        return status;
    }

    ReturnErrorOnFailure(SubscribeAttributes(this, target));

    if (!root.IsMap() || !root["command"])
    {
        ChipLogError(chipToolFuzzing, "Replication failed: Command not found in experiment file.");
        status = CHIP_ERROR_INVALID_ARGUMENT;

        LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
        SetCommandExitStatus(status);
        return status;
    }

    if (root["reported"])
    {
        for (const auto & report : root["reported"])
        {
            types::AttributePathMap dataMap;
            for (const auto & attr : report["data"])
            {
                chip::app::ConcreteAttributePath attributePath = chip::app::ConcreteAttributePath(
                    attr["endpoint"].as<uint16_t>(), attr["cluster"].as<uint32_t>(), attr["attribute"].as<uint32_t>());
                types::AnyType value;
                ReturnErrorOnFailure(utils::LoadAttribute(report["data"], attr, value));
                dataMap[attributePath] = value;
            }
            expectedSubscriptionOutput.push_back(dataMap);
        }
    }

    if (root["response"])
    {
        auto container = fuzz::ContainerType{};
        for (const auto & field : root["response"]["value"])
        {
            auto nestedElement = std::make_shared<fuzz::TLV::DecodedTLVElement>();
            ReturnErrorOnFailure(utils::LoadAttribute(root["response"]["value"], field, nestedElement->content));
            container.push_back(nestedElement);
        }
        expectedResponseOutput = container;
    }

    fuzzer->GoToNextPhase();

    std ::string command = root["command"].as<std::string>();
    std::vector<types::AttributePathMap> reportedData;
    types::AnyType responseData;
    ExecuteCommand<decltype(responseData)>(command.c_str(), &status, &responseData, &reportedData);

    if (status != CHIP_NO_ERROR)
    {
        ChipLogError(chipToolFuzzing, "Replication failed: the command could not be executed.");
        LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
        SetCommandExitStatus(status);
        return status;
    }

    bool reportedDataMatch = true;

    if (reportedData.size() != expectedSubscriptionOutput.size())
    {
        ChipLogError(chipToolFuzzing, "Replication failed: %zu were expected but %zu were received.", expectedSubscriptionOutput.size(),
                     reportedData.size());
        reportedDataMatch = false;
    }
    else
    {
        for (size_t i = 0; i < reportedData.size(); i++)
        {
            for (const auto & [path, expectedValue] : expectedSubscriptionOutput[i])
            {
                if (reportedData[i].find(path) == reportedData[i].end())
                {
                    ChipLogError(chipToolFuzzing,
                                 "Replication failed: attribute (0x%04" PRIX16 ", 0x%08" PRIX32 ", 0x%08" PRIX32
                                 ") was expected but not reported.",
                                 path.mEndpointId, path.mClusterId, path.mAttributeId);
                    status            = CHIP_FUZZER_ERROR_REPLICATION_FAILED;
                    reportedDataMatch = false;
                    break;
                }
                auto observedValue = reportedData[i].find(path)->second;
                if (!Visitors::IsEqual(expectedValue, observedValue))
                {
                    ChipLogError(chipToolFuzzing,
                                 "Replication failed: The value of attribute 0x%08" PRIX32
                                 " (%s) does not match the expected one (%s).",
                                 path.mAttributeId, Visitors::AttributeValueAsString(observedValue).c_str(),
                                 Visitors::AttributeValueAsString(expectedValue).c_str());
                    status            = CHIP_FUZZER_ERROR_REPLICATION_FAILED;
                    reportedDataMatch = false;
                    break;
                }
            }
            if (!reportedDataMatch)
                break;
        }
    }

    if (!reportedDataMatch)
    {
        LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
        SetCommandExitStatus(status);
        return status;
    }

    if (!Visitors::IsEqual(responseData, expectedResponseOutput))
    {
        ChipLogError(chipToolFuzzing, "The response data does not match the expected one.");
        status = CHIP_FUZZER_ERROR_REPLICATION_FAILED;
    }
    else
    {
        ChipLogProgress(chipToolFuzzing, "The experiment was replicated successfully.");
    }

    LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
    SetCommandExitStatus(status);
    return status;
}

CHIP_ERROR FuzzingTuneCommand::RunCommand()
{
    ReturnErrorOnFailure(InitializeFuzzer(mDestinationId, mMinWaitingTime.ValueOr(50U), mWaitingTimeShrinkFactor.ValueOr(0.2),
                                          mWaitingTimeShrinkCommandsInterval.ValueOr(10U), mWaitingTimeGrowthFactor.ValueOr(0.1),
                                          mWaitingTimeGrowthCommandsInterval.ValueOr(20U)));

    CHIP_ERROR status = CHIP_NO_ERROR;
    auto fuzzer       = fuzz::Fuzzer::GetInstance();
    auto dsTracker    = fuzzer->GetDeviceStateTracker();

    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AcquireRemoteDataModel(this, mDestinationId));

    auto * endpointList = dsTracker->List(mDestinationId);
    VerifyOrReturnError(endpointList, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    LogErrorOnFailure(AcquireBasicInformation(this, mDestinationId));
    mDestinationSupportsTCPServer = TestTCPServerSupport(mDestinationId);
    ReturnErrorOnFailure(SubscribeAttributes(this, mDestinationId));

    const fuzz::BasicInformation * nodeInfo = dsTracker->GetNodeInformation(mDestinationId);

    fs::path pGeneratedGrammarsDirectory = GetOutputDirectory() / nodeInfo->ToString() / "grammar";

    fuzz::generation::InputGenerator inputGenerator(nodeInfo, pGeneratedGrammarsDirectory.string());
    fs::path pTestcasesFile = GetOutputDirectory() / nodeInfo->ToString() / "tests.txt";
    inputGenerator.CreateGrammar(dsTracker, mDestinationId);
    inputGenerator.GenerateTestCases(pTestcasesFile, 10000);

    fuzzer->GoToNextPhase();

    std::ifstream file(pTestcasesFile);
    std::string generatedArgs;
    bool tuning = true;
    while (std::getline(file, generatedArgs) && tuning)
    {
        std::string command = "any command-by-id ";
        command += fuzz::generation::InputGenerator::ParseTestCase(mDestinationId, generatedArgs);
        ExecuteCommand(command.c_str(), &status);
        tuning = fuzzer->GetTuner()->Tune();
    }

    file.close();

    ChipLogProgress(chipToolFuzzing, "Tuning completed in %s. A good timeout value for report data is %f ms.",
                    fuzz::GetElapsedTime(fuzzer->GetStatsMonitor()->GetStartTime()).c_str(),
                    fuzzer->GetTuner()->GetCurrentWaitingTime());

    LogErrorOnFailure(chip::DeviceLayer::PlatformMgr().ScheduleWork(ExecuteDeferredCleanups, 0));
    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
}
