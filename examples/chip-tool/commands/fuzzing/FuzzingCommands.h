#pragma once
#include "../common/CHIPCommand.h"
#include "../common/Commands.h"
#include "ForwardDeclarations.h"
#include "Fuzzer.h"

class FuzzingCommand : public CHIPCommand
{
public:
    FuzzingCommand(const char * name, Commands * commandsHandler, const char * helpText,
                   CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand(name, credsIssuerConfig, helpText), mHandler(commandsHandler)
    {
        AddArgument("out", &mOutputDirectory, "Directory where fuzzing grammars, generated test cases, and result files are written.");
    }

    fs::path GetOutputDirectory() const
    {
        if (mOutputDirectory != nullptr)
            return fs::path(mOutputDirectory);

        return fs::path(std::getenv("PW_PROJECT_ROOT")) / "fuzzing_output";
    }

    /////////// CHIPCommand Interface /////////
    chip::System::Clock::Timeout GetWaitDuration() const override { return chip::System::Clock::Seconds16(0); }
    template <typename T = types::AttributePathMap>
    void ExecuteCommand(const char * command, CHIP_ERROR * status, T * responseOutput = nullptr,
                        std::vector<types::AttributePathMap> * reportOutput = nullptr);
    bool TestTCPServerSupport(chip::NodeId id);

    virtual CHIP_ERROR RunCommand() override = 0;
    CHIP_ERROR InitializeFuzzer(chip::NodeId dst, uint64_t tests, fuzz::FuzzerMode mode = fuzz::FuzzerMode::TESTING);
    CHIP_ERROR InitializeFuzzer(chip::NodeId dst, uint16_t minWaiting, double shrinkFactor, uint16_t shrinkCommandsInterval,
                                double growthFactor, uint16_t growthCommandsInterval);

private:
    Commands * mHandler = nullptr;
    char * mOutputDirectory = nullptr;
};

extern template void FuzzingCommand::ExecuteCommand<types::AttributePathMap>(const char * command, CHIP_ERROR * status,
                                                                             types::AttributePathMap * responseOutput,
                                                                             std::vector<types::AttributePathMap> * reportOutput);
extern template void FuzzingCommand::ExecuteCommand<types::AnyType>(const char * command, CHIP_ERROR * status,
                                                                    types::AnyType * responseOutput,
                                                                    std::vector<types::AttributePathMap> * reportOutput);

/**
 * @brief Starts the fuzzing process that can then run other commands.
 */
class FuzzingStartCommand : public FuzzingCommand
{
public:
    FuzzingStartCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("start", commandsHandler, "Start the fuzzing process that can then run other commands.", credsIssuerConfig)
    {
        AddArgument("destination-id", 0, UINT64_MAX, &mDestinationId,
                    "64-bit node or group identifier.\n  Group identifiers are detected by being in the 0xFFFF'FFFF'FFFF'xxxx "
                    "range. Group fuzzing is not yet supported.");
        AddArgument("tests", 0, UINT64_MAX, &mTests, "Number of test cases to run the fuzzer for");
        AddArgument("report-timeout", 0, UINT64_MAX, &mReportTimeout,
                    "Subscription report timeout in milliseconds, which resets after every report and expires when no more reports "
                    "are received.");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    chip::NodeId mDestinationId;
    uint64_t mTests                    = 1000U;
    uint64_t mReportTimeout            = 250U;
    bool mDestinationSupportsTCPServer = false;
};

/**
 * @brief Checks if, given a dumped device state and a command, the command response and eventual reported attributes are
 * reproducible.
 */
class FuzzingReplicateCommand : public FuzzingCommand
{
public:
    FuzzingReplicateCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("replicate", commandsHandler,
                       "Checks if, given a dumped device state and a command, the command response and eventual reported "
                       "attributes are replicable.",
                       credsIssuerConfig)
    {
        AddArgument("experiment-file", &mExperimentFile,
                    "Path to the experiment to reproduce. Syntax: "
                    "<vendorName>_<vendorId>_<productId>_<hwVersion>_<swVersion>/<endpointId>/<clusterId>/<commandId>/"
                    "<timestamp>_<statusCode>.yaml");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    char * mExperimentFile = nullptr;
};

class FuzzingTuneCommand : public FuzzingCommand
{
public:
    FuzzingTuneCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("tune", commandsHandler,
                       "Tunes the fuzzer to return an approximate value for the minimum waiting time for report data.",
                       credsIssuerConfig)
    {
        AddArgument("destination-id", 0, UINT64_MAX, &mDestinationId,
                    "64-bit node or group identifier.\n  Group identifiers are detected by being in the 0xFFFF'FFFF'FFFF'xxxx "
                    "range. Group fuzzing is not yet supported.");
        AddArgument("minWaitingTime", 0, UINT16_MAX, &mMinWaitingTime,
                    "Minimum limit for waiting time for report data in milliseconds.");
        AddArgument("shrinkFactor", 0.01, 0.5, &mWaitingTimeShrinkFactor,
                    "Factor by which the waiting time for report data will shrink.");
        AddArgument("shrinkCommandsInterval", 10U, 100U, &mWaitingTimeShrinkCommandsInterval,
                    "Number of commands after which the waiting time for report data will shrink.");
        AddArgument("growthFactor", 0.01, 0.5, &mWaitingTimeGrowthFactor,
                    "Factor by which the waiting time for report data will grow.");
        AddArgument("growthCommandsInterval", 10U, 100U, &mWaitingTimeGrowthCommandsInterval,
                    "Number of commands after which the waiting time for report data will grow.");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    chip::NodeId mDestinationId;
    chip::Optional<uint16_t> mMinWaitingTime;
    chip::Optional<double> mWaitingTimeShrinkFactor;
    chip::Optional<uint16_t> mWaitingTimeShrinkCommandsInterval;
    chip::Optional<double> mWaitingTimeGrowthFactor;
    chip::Optional<uint16_t> mWaitingTimeGrowthCommandsInterval;
    bool mDestinationSupportsTCPServer = false;
};
