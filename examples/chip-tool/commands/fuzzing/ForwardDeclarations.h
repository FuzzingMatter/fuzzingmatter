#pragma once
#include <app/ConcreteAttributePath.h>
#include <app/ConcreteCommandPath.h>
#include <filesystem>
#include <functional>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <lib/core/TLV.h>
#include <optional>
#include <protocols/interaction_model/Constants.h>
#include <string>
#include <unordered_set>
#include <variant>

class FuzzingCommand;
class FuzzingStartCommand;
class FuzzingReplicateCommand;
class FuzzingTuneCommand;
namespace chip {
namespace fuzzing {

using IMStatus = chip::Protocols::InteractionModel::Status;

namespace TLV {
using TLVType = chip::TLV::TLVType;
using TLVTag  = chip::TLV::TLVTagControl;
class TLVDataPayloadHelper;
class DecodedTLVElement;
class DecodedTLVElementPrettyPrinter;

inline TLVTag ExtractTagFromControlByte(uint16_t controlByte);
inline uint8_t ExtractSizeFromControlByte(TLVType type, uint16_t controlByte);
} // namespace TLV

// CHIPFuzzer core errors (0x01 - 0x3F)
#define CHIP_FUZZER_ERROR_NOT_RUNNING CHIP_APPLICATION_ERROR(0x01)
#define CHIP_FUZZER_ERROR_NOT_FOUND CHIP_APPLICATION_ERROR(0x02)
#define CHIP_FUZZER_ERROR_NOT_IMPLEMENTED CHIP_APPLICATION_ERROR(0x03)
#define CHIP_FUZZER_ERROR_SYSTEM_IO CHIP_APPLICATION_ERROR(0x04)
#define CHIP_FUZZER_ERROR_CORE_INITIALIZATION_FAILED CHIP_APPLICATION_ERROR(0x05)
#define CHIP_FUZZER_ERROR_NODE_SCAN_FAILED CHIP_APPLICATION_ERROR(0x06)
#define CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH CHIP_APPLICATION_ERROR(0x07)
#define CHIP_FUZZER_ERROR_ABORTED CHIP_APPLICATION_ERROR(0x08)
#define CHIP_FUZZER_ERROR_REPLICATION_FAILED CHIP_APPLICATION_ERROR(0x09)
// CHIPFuzzer context-related errors (0x40 - 0x7F)
#define CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT CHIP_APPLICATION_ERROR(0x40)
#define CHIP_FUZZER_ERROR_END_OF_CONTEXT CHIP_APPLICATION_ERROR(0x41)
#define CHIP_FUZZER_ERROR_CONTEXT_LOCKED CHIP_APPLICATION_ERROR(0x42)
#define CHIP_FUZZER_ERROR_BAD_CONTEXT_STATE CHIP_APPLICATION_ERROR(0x43)
#define CHIP_FUZZER_ERROR_SUBSCRIPTION_RESPONSE_TIMEOUT CHIP_APPLICATION_ERROR(0x44)

inline constexpr uint64_t kMaxConsecutiveTimeouts = 10;
using PrimitiveType = std::variant<std::monostate, bool, char *, float, double, chip::NullOptionalType, int8_t, int16_t, int32_t,
                                   int64_t, uint8_t, uint16_t, uint32_t, uint64_t, std::string>;

// Composite types
using ContainerType = std::vector<std::shared_ptr<TLV::DecodedTLVElement>>;

namespace generation {
class InputGenerator;
} // namespace generation

namespace types {

// Helper types used as keys in maps
template <typename T, typename... Args>
struct ExtendedVariant;

struct MapKeyHasher;
class MapKeyEqualizer;
struct SetKeyHasher;

struct ExecutionStats;
enum class Access : uint16_t;
struct FuzzerObservation;
} // namespace types
namespace utils {
class DefaultValuesGenerator;
static const std::vector<std::pair<TLV::TLVType, uint8_t>> supportedTypes;
} // namespace utils

// Main objects
class Fuzzer;
class ContextManager;
struct FuzzerContext;
class ContextStatus;
enum class FuzzerPhase : uint8_t;
enum class FuzzerMode : uint8_t;

struct AttributeFactory;
struct AttributeWrapper;
class AttributeState;
struct ClusterState;
struct EndpointState;
struct NodeState;
struct BasicInformation;
struct DeviceState;
struct CommandHistoryEntry;
class DeviceStateTracker;
class CallbackInterceptor;
class StatsMonitor;
class OutputLogger;
class Tuner;
} // namespace fuzzing
} // namespace chip

namespace fuzz  = chip::fuzzing;
namespace gen   = chip::fuzzing::generation;
namespace utils = chip::fuzzing::utils;
namespace TLV   = chip::fuzzing::TLV;
namespace fs    = std::filesystem;
