#pragma once
#include "AttributeFactory.h"
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <unordered_map>

namespace chip {
namespace fuzzing {
class AttributeState
{
public:
    AttributeState() = default;
    // Copy constructor
    AttributeState(const AttributeState & other)
    {
        if (other.mValue)
        {
            mValue = std::make_unique<AttributeWrapper>(*other.mValue);
        }
        if (other.mOldValue)
        {
            mOldValue = std::make_unique<AttributeWrapper>(*other.mOldValue);
        }
    }
    // Move constructor
    AttributeState(AttributeState && other) noexcept : mValue(std::move(other.mValue)), mOldValue(std::move(other.mOldValue)) {}
    // Copy assignment operator
    AttributeState & operator=(const AttributeState & other)
    {
        if (this != &other)
        {
            mValue.reset();
            mOldValue.reset();
            if (other.mValue)
            {
                mValue = std::make_unique<AttributeWrapper>(*other.mValue);
            }
            if (other.mOldValue)
            {
                mOldValue = std::make_unique<AttributeWrapper>(*other.mOldValue);
            }
        }
        return *this;
    }
    // Move assignment operator
    AttributeState & operator=(AttributeState && other) noexcept
    {
        if (this != &other)
        {
            mValue    = std::move(other.mValue);
            mOldValue = std::move(other.mOldValue);
        }
        return *this;
    }
    AttributeState(TLV::TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality)
    {
        mValue = AttributeFactory::Create(aType, bytes, aQuality);
    }
    AttributeState(TLV::TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality, types::AnyType && value)
    {
        mValue = AttributeFactory::Create(aType, std::move(value), bytes, aQuality);
    }
    const types::AnyType & ReadCurrent()
    {
        VerifyOrReturnValue(mReadable && (mValue != nullptr), kInvalidValue);
        return mValue->Read();
    }
    const types::AnyType & ReadLast()
    {
        VerifyOrReturnValue(mReadable && (mOldValue != nullptr), kInvalidValue);
        return mOldValue->Read();
    }
    CHIP_ERROR Write(types::AnyType && value)
    {
        VerifyOrReturnError(mValue != nullptr, CHIP_ERROR_INCORRECT_STATE);
        // Move the current value to the older pointer AFTER the new value write has been successful (for state consistency)
        auto old = std::make_shared<AttributeWrapper>(*mValue);
        ReturnErrorOnFailure(mValue->Write(std::move(value)));
        mOldValue = std::move(old);
        mReadable = true;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR SetAccess(types::Access access)
    {
        mValue->access |= static_cast<uint16_t>(access);
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR RemoveAccess(types::Access access)
    {
        mValue->access &= ~static_cast<uint16_t>(access);
        return CHIP_NO_ERROR;
    }

    bool HasAccess(types::Access access) { return mValue->access & static_cast<uint16_t>(access); }

    CHIP_ERROR LazyInitialize(TLV::TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality, types::AnyType && value)
    {
        mValue = std::move(AttributeFactory::Create(aType, std::move(value), bytes, aQuality));
        VerifyOrReturnError(mValue != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
        return CHIP_NO_ERROR;
    }

    // If the attribute is unreadable, any read access to it is denied
    void ToggleBlockReads() { mReadable = !mReadable; }
    bool IsReadable() { return mReadable; }

private:
    // Some attributes may be blocked or uninitialized, e.g. when reading them, the device returns a 0x01 status code (FAILURE)
    bool mReadable                              = true;
    std::shared_ptr<AttributeWrapper> mValue    = nullptr;
    std::shared_ptr<AttributeWrapper> mOldValue = nullptr;
};

struct DeviceTypeStruct
{
    DeviceTypeId id;
    uint16_t revision;
};

struct ClusterState
{
    ClusterId clusterId;
    uint16_t clusterRevision;
    std::unordered_map<AttributeId, AttributeState> attributes;
    std::unordered_map<CommandId, types::CommandSpecification> serverCommands;
};

struct EndpointState
{
    EndpointId endpointId;
    std::vector<DeviceTypeStruct> deviceTypes;
    std::unordered_map<ClusterId, ClusterState> clusters;
};

struct BasicInformation
{
    std::optional<uint16_t> dmRevision           = std::nullopt;
    std::optional<std::string> vendorName        = std::nullopt;
    std::optional<uint16_t> vendorId             = std::nullopt;
    std::optional<uint16_t> productId            = std::nullopt;
    std::optional<uint16_t> hwVersion            = std::nullopt;
    std::optional<uint32_t> swVersion            = std::nullopt;
    std::optional<std::string> manufacturingDate = std::nullopt;
    std::optional<std::string> serialNumber      = std::nullopt;
    std::string ToString() const
    {
        std::string vendor = vendorName.value_or("na");
        vendor.erase(std::remove_if(vendor.begin(), vendor.end(), [](char c) { return c == ' ' || c == '_' || c == '-'; }), vendor.end());
        std::ostringstream s(vendor, std::ios_base::ate);
        s << std::hex << "_" << vendorId.value_or(0xFFFF) << "_" << productId.value_or(0xFFFF) << "_" << hwVersion.value_or(0xFFFF)
          << "_" << swVersion.value_or(0xFFFFFFFF);
        return s.str();
    }
};

struct NodeState
{
    NodeId nodeId;
    BasicInformation nodeInfo;
    std::unordered_map<EndpointId, EndpointState> endpoints;
};

struct DeviceState
{
public:
    std::unordered_map<NodeId, NodeState> nodes;

    NodeState * operator()(NodeId id);
    EndpointState * operator()(NodeId node, EndpointId endpoint);
    ClusterState * operator()(NodeId node, EndpointId endpoint, ClusterId cluster);
};

/**
 * @class DeviceStateTracker
 * @brief Manages the state of devices and provides methods for accessing and modifying device attributes.
 *
 * The DeviceStateTracker class is responsible for tracking and managing the state of devices. It provides methods for
 * retrieving and setting attributes of a device, as well as accessing the clusters associated with a device's
 * endpoint.
 *
 * NOTE: Changes to the device state through this class are not reflected in the actual remote device state.
 *
 * TODO: Extend this to manage state of groups of devices.
 */
class DeviceStateTracker
{
public:
    DeviceStateTracker() {};
    ~DeviceStateTracker() {};

    const types::AnyType & ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                         bool current = true);
    AttributeState & GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    void WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, types::AnyType && aValue);
    types::CommandSpecification * ReadCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command);
    void WriteToCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command, bool generatesReport);
    void WriteToCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command, types::Access access);
    void SetAttributeAccess(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, types::Access access);

    bool CommandHasAccess(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command, types::Access access);

    const BasicInformation * GetNodeInformation(NodeId node);
    std::unordered_map<NodeId, NodeState> * List();
    std::unordered_map<EndpointId, EndpointState> * List(NodeId node);
    std::unordered_map<ClusterId, ClusterState> * List(NodeId node, EndpointId endpoint);
    std::unordered_map<AttributeId, AttributeState> * List(NodeId node, EndpointId endpoint, ClusterId cluster);

    // The Add methods are used to add new nodes, endpoints, clusters, and attributes to the device state.
    void Add(NodeId node);
    void Add(NodeId node, BasicInformation info);
    void Add(NodeId node, EndpointId endpoint);
    void Add(NodeId node, EndpointId endpoint, DeviceTypeStruct deviceType);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint16_t revision = 5U);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint32_t leaf, bool isCommand = false,
             std::optional<types::Access> commandAccess = std::nullopt);

    /**
     * @brief Loads a device state snapshot from a YAML file. If the sync flag is set to true, tries to synchronize the remote state
     * with the loaded state issuing commands with the provided handler.
     */
    CHIP_ERROR Load(YAML::Node & root, bool sync = false, FuzzingCommand * handler = nullptr, bool partial = false,
                    chip::app::ConcreteClusterPath cluster = chip::app::ConcreteClusterPath());

    /**
     * @brief Returns the number of (endpoint, cluster, command) paths in the device state.
     */
    size_t GetTotalCommands();

    /**
     * @brief Returns the number of (endpoint, cluster, attribute) paths in the device state.
     */
    size_t GetTotalAttributes();

    /**
     * @brief Returns the total number of paths in the device state.
     */
    size_t GetTotalPaths() { return GetTotalCommands() + GetTotalAttributes(); }

    chip::Optional<chip::SubscriptionId> IsSubscriptionActive(SubscriptionId id)
    {
        auto it = std::find(mActiveSubscriptions.begin(), mActiveSubscriptions.end(), id);
        return it != mActiveSubscriptions.end() ? chip::Optional<chip::SubscriptionId>(*it) : chip::NullOptional;
    }

    void AddSubscription(SubscriptionId id) { mActiveSubscriptions.push_back(id); }

private:
    DeviceState mDeviceState;
    std::vector<chip::SubscriptionId> mActiveSubscriptions;
    CHIP_ERROR Sync(NodeId target, chip::app::ConcreteAttributePath & path, const YAML::Node & parentNode,
                    const YAML::detail::iterator_value & localAttrData, types::AnyType & value, FuzzingCommand * handler);
};

struct CommandHistoryEntry
{
    size_t index;
    std::string command;
    CHIP_ERROR statusResponse;
    fuzz::FuzzerPhase fuzzerPhase;
};
} // namespace fuzzing
} // namespace chip
