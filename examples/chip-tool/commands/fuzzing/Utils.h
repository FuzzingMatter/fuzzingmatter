#pragma once
#include "ForwardDeclarations.h"
#include <json/json.h>
#include <numeric>
#include <yaml-cpp/yaml.h>

namespace chip {
namespace fuzzing {
namespace types {
template <typename T, typename... Args>
struct ExtendedVariant;

template <typename... Args0, typename... Args1>
struct ExtendedVariant<std::variant<Args0...>, Args1...>
{
    using type = std::variant<Args0..., Args1...>;
};

template <typename... Args0, typename... Args1>
struct ExtendedVariant<std::variant<Args0...>, std::variant<Args1...>>
{
    using type = std::variant<Args0..., Args1...>;
};

using AnyType          = typename ExtendedVariant<PrimitiveType, ContainerType>::type;
using AttributePathMap = std::unordered_map<chip::app::ConcreteAttributePath, AnyType, MapKeyHasher>;

struct FuzzerObservation
{
    std::string mCommand;
    chip::app::ConcreteCommandPath mCommandPath;
    CHIP_ERROR mStatusResponse;
    std::shared_ptr<types::AnyType> mResponseData;
    std::vector<AttributePathMap> mReportedData;
};

enum class Access : uint16_t
{
    kRead            = 0x1,
    kWrite           = 0x2,
    kView            = 0x4,
    kOperate         = 0x8,
    kManage          = 0x10,
    kAdminister      = 0x20,
    kFabricScoped    = 0x40,
    kFabricSensitive = 0x80,
    kTimed           = 0x100,
};
struct CommandSpecification
{
    CommandId id;
    uint16_t access        = static_cast<uint16_t>(Access::kOperate);
    bool canGenerateReport = true;
    bool HasAccess(Access requested) { return this->access & static_cast<uint16_t>(requested); }
};

struct MapKeyHasher
{
    std::size_t operator()(const chip::app::ConcreteAttributePath & path) const
    {
        return std::hash<chip::EndpointId>{}(path.mEndpointId) ^ std::hash<chip::ClusterId>{}(path.mClusterId) ^
            std::hash<chip::AttributeId>{}(path.mAttributeId);
    }

    std::size_t operator()(const chip::app::ConcreteCommandPath & path) const
    {
        return std::hash<chip::EndpointId>{}(path.mEndpointId) ^ std::hash<chip::ClusterId>{}(path.mClusterId) ^
            std::hash<chip::CommandId>{}(path.mCommandId);
    }

    std::size_t operator()(const chip::app::ConcreteClusterPath & path) const
    {
        return std::hash<chip::EndpointId>{}(path.mEndpointId) ^ std::hash<chip::ClusterId>{}(path.mClusterId);
    }

    std::size_t operator()(const std::pair<TLV::TLVType, uint8_t> & key) const
    {
        return std::hash<int16_t>{}(static_cast<int16_t>(key.first)) ^ std::hash<uint8_t>{}(key.second);
    }

    std::size_t operator()(const FuzzerObservation & k) const
    {
        uint64_t reportedDataSum =
            std::accumulate(k.mReportedData.begin(), k.mReportedData.end(), 0, [&](uint64_t acc, auto & map) {
                std::vector<uint64_t> attributePathMapSums(map.size());
                std::transform(map.begin(), map.end(), attributePathMapSums.begin(), [&](auto & el) {
                    return static_cast<uint64_t>(el.first.mEndpointId) + static_cast<uint64_t>(el.first.mClusterId) +
                        static_cast<uint64_t>(el.first.mAttributeId);
                });
                auto sum = std::reduce(attributePathMapSums.begin(), attributePathMapSums.end());
                return acc + sum;
            });

        return std::hash<uint32_t>{}(k.mCommandPath.mEndpointId ^ k.mCommandPath.mClusterId ^ k.mCommandPath.mCommandId) ^
            std::hash<uint32_t>{}(k.mStatusResponse.AsInteger()) ^ std::hash<uint64_t>{}(reportedDataSum);
    }

    std::size_t operator()(const CHIP_ERROR & k) const { return std::hash<uint32_t>{}(k.AsInteger()); }
};

class MapKeyEqualizer
{
public:
    bool operator()(const FuzzerObservation & k0, const FuzzerObservation & k1) const
    {
        if (!IsResponseDataEqual(k0.mResponseData, k1.mResponseData))
            return false;
        if (k0.mReportedData.size() != k1.mReportedData.size())
            return false;
        for (size_t i = 0; i < k0.mReportedData.size(); i++)
        {
            if (!AreReportedDataAttributePathsEqual(k0.mReportedData[i], k1.mReportedData[i]))
            {
                return false;
            }
        }
        return k0.mCommandPath == k1.mCommandPath && k0.mStatusResponse == k1.mStatusResponse;
    }

private:
    bool AreReportedDataAttributePathsEqual(const AttributePathMap & m0, const AttributePathMap & m1) const;

    bool IsResponseDataEqual(const std::shared_ptr<AnyType> v0, const std::shared_ptr<AnyType> v1) const;
};

/*
    @brief Collects time statistics on the execution of a command.

    Important intervals and relative events:

        * [issTime, txTime]: fuzzer initializes the context, CHIPTool schedules the command in the Matter queue and a SendCommand
   request is issued.

        * [txTime, waitForRxTime]: fuzzer starts waiting for response.

        * [waitForRxTime, rxTime]: CHIPTool takes the command request, codifies the request message, sends it to the device through
        the network, waits for the response to come back, processes it and makes it available to the fuzzer + network overhead
   (latency).

        * [rxTime, waitForRepRxTime]: fuzzer processes the response, starts waiting for eventual subscription reports to come back.

        * [waitForRepRxTime, repRxTime]: CHIPTool looks for reports on the Matter queue, decodes them and makes them available to
   the fuzzer.

        * [repRxTime, finishTime]: subscription data is processed and connected operations are executed, fuzzer closes the context.

        * [finishTime, issTime of next command]: fuzzer reads the file to take the next test command and prepares it to be launched.
*/
struct ExecutionStats
{
    bool responseTimedOut     = false;
    bool subscriptionTimedOut = false;
    // Timestamp when the context was initialized (command is not sent yet)
    std::chrono::steady_clock::time_point issTime;
    // Timestamp when the command request callback was scheduled in the Matter queue
    std::chrono::steady_clock::time_point schTime;
    // Timestamp when the request was sent to the device
    std::chrono::steady_clock::time_point txTime;
    // Timestamp when the fuzzer started waiting for the response
    std::chrono::steady_clock::time_point waitForRxTime;
    // Timestamp when the response was received from the device
    std::chrono::steady_clock::time_point rxTime;
    // Timestamp when the fuzzer started waiting for the reports
    std::chrono::steady_clock::time_point waitForRepRxTime;
    // Timestamp when the reports were received from the device
    std::chrono::steady_clock::time_point repRxTime;
    // Timestamp when the command context was closed
    std::chrono::steady_clock::time_point finishTime;
};

} // namespace types

namespace utils {

class DefaultValuesGenerator
{
public:
    DefaultValuesGenerator()
    {
        const uint64_t float1 = 0x3f80000000000000; // 1.0 float
        const uint64_t smallestDouble =
            0x3e00000000000001; // Smallest double precision float greater than 32-bit representable float

        std::pair<TLV::TLVType, uint8_t> key = { TLV::TLVType::kTLVType_ByteString, 4 };
        kDefaultValues[key].resize((UINT32_MAX >> 16) << 1, 'F');
        kDefaultValues[key].insert(0, "hex:");

        key = { TLV::TLVType::kTLVType_ByteString, 2 };
        kDefaultValues[key].resize((UINT32_MAX >> 24) << 1, 'F');
        kDefaultValues[key].insert(0, "hex:");

        key = { TLV::TLVType::kTLVType_ByteString, 1 };
        kDefaultValues[key].resize((UINT8_MAX - 1) << 1, 'F');
        kDefaultValues[key].insert(0, "hex:");

        key                 = { TLV::TLVType::kTLVType_FloatingPointNumber, 8 };
        kDefaultValues[key] = "d:" + std::to_string(*reinterpret_cast<const double *>(&smallestDouble));

        key                 = { TLV::TLVType::kTLVType_FloatingPointNumber, 4 };
        kDefaultValues[key] = "f:" + std::to_string(*reinterpret_cast<const float *>(&float1));

        key                 = { TLV::TLVType::kTLVType_SignedInteger, 8 };
        kDefaultValues[key] = "s:" + std::to_string(INT64_MAX >> 32);

        key                 = { TLV::TLVType::kTLVType_SignedInteger, 4 };
        kDefaultValues[key] = "s:" + std::to_string(INT32_MAX >> 16);

        key                 = { TLV::TLVType::kTLVType_SignedInteger, 2 };
        kDefaultValues[key] = "s:" + std::to_string(INT16_MAX >> 8);

        key                 = { TLV::TLVType::kTLVType_SignedInteger, 1 };
        kDefaultValues[key] = "s:1";

        key                 = { TLV::TLVType::kTLVType_UnsignedInteger, 8 };
        kDefaultValues[key] = std::to_string(UINT64_MAX >> 32);

        key                 = { TLV::TLVType::kTLVType_UnsignedInteger, 4 };
        kDefaultValues[key] = std::to_string(UINT32_MAX >> 16);

        key                 = { TLV::TLVType::kTLVType_UnsignedInteger, 2 };
        kDefaultValues[key] = std::to_string(UINT16_MAX >> 8);

        key                 = { TLV::TLVType::kTLVType_UnsignedInteger, 1 };
        kDefaultValues[key] = "0";

        key = { TLV::TLVType::kTLVType_UTF8String, 4 };
        kDefaultValues[key].resize(UINT32_MAX >> 16, 'a');

        key = { TLV::TLVType::kTLVType_UTF8String, 2 };
        kDefaultValues[key].resize(UINT32_MAX >> 24, 'a');

        key = { TLV::TLVType::kTLVType_UTF8String, 1 };
        kDefaultValues[key].resize(UINT8_MAX, 'a');
    }

    static DefaultValuesGenerator & GetInstance()
    {
        static DefaultValuesGenerator instance;
        return instance;
    }

    std::string GetDefaultValue(const std::pair<TLV::TLVType, uint8_t> & key) { return kDefaultValues[key]; }
    void AddDefaultValueToPayload(Json::Value & payload, std::string id, chip::TLV::TLVType type, uint8_t size);

private:
    std::unordered_map<std::pair<TLV::TLVType, uint8_t>, std::string, types::MapKeyHasher> kDefaultValues;
};

CHIP_ERROR LoadAttribute(const YAML::Node & parent, const YAML::detail::iterator_value & attribute, types::AnyType & value);
CHIP_ERROR LoadAttributeAsArgument(const YAML::Node & parent, const YAML::detail::iterator_value & attribute, std::string & arg);

} // namespace utils

inline types::AnyType kInvalidValue = std::monostate();

void Indent(size_t indent);
std::string GetElapsedTime(std::chrono::steady_clock::time_point startTime);
bool IsManufacturerSpecificTestingCluster(ClusterId cluster);

const std::vector<std::pair<TLV::TLVType, uint8_t>> supportedTypes{
    { TLV::TLVType::kTLVType_Array, 0 },
    { TLV::TLVType::kTLVType_Boolean, 0 },
    { TLV::TLVType::kTLVType_ByteString, 8 },
    { TLV::TLVType::kTLVType_ByteString, 4 },
    { TLV::TLVType::kTLVType_ByteString, 2 },
    { TLV::TLVType::kTLVType_ByteString, 1 },
    { TLV::TLVType::kTLVType_FloatingPointNumber, 8 },
    { TLV::TLVType::kTLVType_FloatingPointNumber, 4 },
    { TLV::TLVType::kTLVType_List, 0 },
    { TLV::TLVType::kTLVType_Null, 0 },
    { TLV::TLVType::kTLVType_Structure, 0 },
    { TLV::TLVType::kTLVType_SignedInteger, 8 },
    { TLV::TLVType::kTLVType_SignedInteger, 4 },
    { TLV::TLVType::kTLVType_SignedInteger, 2 },
    { TLV::TLVType::kTLVType_SignedInteger, 1 },
    { TLV::TLVType::kTLVType_UnsignedInteger, 8 },
    { TLV::TLVType::kTLVType_UnsignedInteger, 4 },
    { TLV::TLVType::kTLVType_UnsignedInteger, 2 },
    { TLV::TLVType::kTLVType_UnsignedInteger, 1 },
    { TLV::TLVType::kTLVType_UTF8String, 8 },
    { TLV::TLVType::kTLVType_UTF8String, 4 },
    { TLV::TLVType::kTLVType_UTF8String, 2 },
    { TLV::TLVType::kTLVType_UTF8String, 1 },
};
} // namespace fuzzing
} // namespace chip

namespace types = chip::fuzzing::types;
