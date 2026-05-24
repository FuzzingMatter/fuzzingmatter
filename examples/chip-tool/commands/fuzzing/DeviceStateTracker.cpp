#include "DeviceStateTracker.h"
#include "FuzzingCommands.h"
#include "Visitors.h"
#include "tlv/DecodedTLVElement.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <fstream>
// This header has exception handling code that is not compatible with -fno-exceptions (see BUILD.gn)
#include <yaml-cpp/yaml.h>

namespace fuzz = chip::fuzzing;

namespace {
template <typename K, typename V>
V * ReadValueOrNull(std::unordered_map<K, V> & map, K id)
{
    auto found = map.find(id);
    VerifyOrReturnValue(found != map.end(), nullptr);
    return &(found->second);
}

// Variadic variant of ReadValueOrNull
template <typename Map, typename K>
auto * ReadValueOrNull(Map & map, const K id)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return &(found->second);
}

template <typename Map, typename K, typename... Path>
auto * ReadValueOrNull(Map & map, const K id, const Path... ids)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return ReadValueOrNull(found->second, ids...);
}
// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K>
auto & ReadValueOrDefault(Map * map, const K id)
{
    VerifyOrDieWithSave(map != nullptr);
    return (*map)[id];
}
template <typename Map, typename K, typename... Path>
auto & ReadValueOrDefault(Map * map, const K id, const Path... ids)
{
    VerifyOrDieWithSave(map != nullptr);
    return ReadValueOrDefault(&(*map)[id], ids...);
}

// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K, typename V>
bool WriteValue(Map & map, const K id, const V & aValue)
{
    return map.emplace(id, aValue)->second;
}
template <typename Map, typename K, typename V, typename... Path>
bool WriteValue(Map & map, const K id, const Path... ids, const V & aValue)
{
    return WriteValue(map[id], ids...);
}
} // namespace

fuzz::NodeState * fuzz::DeviceState::operator()(NodeId id)
{
    return ReadValueOrNull(nodes, id);
}

fuzz::EndpointState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint)
{
    VerifyOrReturnValue((*this)(node) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node)->endpoints, endpoint);
}

fuzz::ClusterState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint, ClusterId cluster)
{
    VerifyOrReturnValue((*this)(node, endpoint) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node, endpoint)->clusters, cluster);
}

const types::AnyType & fuzz::DeviceStateTracker::ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                               AttributeId attribute, bool current)
{
    VerifyOrReturnValue(mDeviceState(node, endpoint, cluster) != nullptr, kInvalidValue);
    AttributeState * attributeState = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    VerifyOrReturnValue(attributeState != nullptr, kInvalidValue);
    return current ? attributeState->ReadCurrent() : attributeState->ReadLast();
}
fuzz::AttributeState & fuzz::DeviceStateTracker::GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                                   AttributeId attribute)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    return ReadValueOrDefault(&mDeviceState(node, endpoint, cluster)->attributes, attribute);
}

CHIP_ERROR fuzz::DeviceStateTracker::WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                                    types::AnyType && aValue)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    AttributeState & attributeState = ReadValueOrDefault(&mDeviceState(node, endpoint, cluster)->attributes, attribute);
    ReturnErrorOnFailure(attributeState.Write(std::move(aValue)));
    return CHIP_NO_ERROR;
}

types::CommandSpecification * fuzz::DeviceStateTracker::ReadCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                                        CommandId command)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    return ReadValueOrNull(mDeviceState(node, endpoint, cluster)->serverCommands, command);
}

void fuzz::DeviceStateTracker::WriteToCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command,
                                                  types::Access access)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    auto * commandSpec = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->serverCommands, command);
    VerifyOrReturn(commandSpec != nullptr);
    commandSpec->access |= static_cast<uint16_t>(access);
}

void fuzz::DeviceStateTracker::WriteToCommandSpec(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command,
                                                  bool generatesReport)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    auto * commandSpec = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->serverCommands, command);
    VerifyOrReturn(commandSpec != nullptr);
    commandSpec->canGenerateReport = generatesReport;
}

void fuzz::DeviceStateTracker::SetAttributeAccess(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                                  types::Access access)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    auto * attributeSpec = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    VerifyOrReturn(attributeSpec != nullptr);
    LogErrorOnFailure(attributeSpec->SetAccess(access));
}

bool fuzz::DeviceStateTracker::CommandHasAccess(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command,
                                                types::Access access)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    auto commandSpec = ReadValueOrDefault(&mDeviceState(node, endpoint, cluster)->serverCommands, command);
    return commandSpec.HasAccess(access);
}

const fuzz::BasicInformation * fuzz::DeviceStateTracker::GetNodeInformation(NodeId node)
{
    VerifyOrDieWithSave(mDeviceState(node) != nullptr);
    return &mDeviceState(node)->nodeInfo;
}
std::unordered_map<chip::NodeId, fuzz::NodeState> * fuzz::DeviceStateTracker::List()
{
    return &mDeviceState.nodes;
}
std::unordered_map<chip::EndpointId, fuzz::EndpointState> * fuzz::DeviceStateTracker::List(NodeId node)
{
    VerifyOrDieWithSave(mDeviceState(node) != nullptr);
    return &mDeviceState(node)->endpoints;
}
std::unordered_map<chip::ClusterId, fuzz::ClusterState> * fuzz::DeviceStateTracker::List(NodeId node, EndpointId endpoint)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint) != nullptr);
    return &mDeviceState(node, endpoint)->clusters;
}
std::unordered_map<chip::AttributeId, fuzz::AttributeState> * fuzz::DeviceStateTracker::List(NodeId node, EndpointId endpoint,
                                                                                             ClusterId cluster)
{
    VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster) != nullptr);
    return &mDeviceState(node, endpoint, cluster)->attributes;
}

// TODO: Consider variadic refactoring
void fuzz::DeviceStateTracker::Add(NodeId node)
{
    VerifyOrReturn(mDeviceState(node) == nullptr);
    NodeState state{};
    VerifyOrDieWithSave(mDeviceState.nodes.emplace(node, state).second);
}

void fuzz::DeviceStateTracker::Add(NodeId node, BasicInformation aInfo)
{
    if (mDeviceState(node) == nullptr)
        Add(node);

    BasicInformation & nodeInfo = mDeviceState(node)->nodeInfo;

    if (!nodeInfo.dmRevision.has_value())
        nodeInfo.dmRevision = aInfo.dmRevision;

    if (!nodeInfo.vendorId.has_value())
        nodeInfo.vendorId = aInfo.vendorId;

    if (!nodeInfo.hwVersion.has_value())
        nodeInfo.hwVersion = aInfo.hwVersion;

    if (!nodeInfo.productId.has_value())
        nodeInfo.productId = aInfo.productId;

    if (!nodeInfo.swVersion.has_value())
        nodeInfo.swVersion = aInfo.swVersion;

    if (!nodeInfo.vendorName.has_value())
        nodeInfo.vendorName = aInfo.vendorName;

    if (!nodeInfo.manufacturingDate.has_value())
        nodeInfo.manufacturingDate = aInfo.manufacturingDate;

    if (!nodeInfo.serialNumber.has_value())
        nodeInfo.serialNumber = aInfo.serialNumber;
}

void fuzz::DeviceStateTracker::Add(NodeId node, EndpointId endpoint)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId);
    VerifyOrReturn((mDeviceState(node) != nullptr) && (mDeviceState(node, endpoint) == nullptr));
    EndpointState state{};
    state.endpointId = endpoint;
    VerifyOrDieWithSave(mDeviceState(node)->endpoints.emplace(endpoint, state).second);
}

void fuzz::DeviceStateTracker::Add(NodeId node, EndpointId endpoint, DeviceTypeStruct deviceType)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (deviceType.id != kInvalidClusterId));
    VerifyOrReturn(mDeviceState(node) != nullptr);
    if (mDeviceState(node, endpoint) != nullptr)
    {
        mDeviceState(node, endpoint)->deviceTypes.push_back(deviceType);
    }
    else
    {
        EndpointState state{};
        state.endpointId  = endpoint;
        state.deviceTypes = std::vector<DeviceTypeStruct>();
        VerifyOrDieWithSave(mDeviceState(node)->endpoints.emplace(endpoint, state).second);
    }
}

void fuzz::DeviceStateTracker::Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint16_t revision)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (cluster != kInvalidClusterId));
    VerifyOrReturn((mDeviceState(node, endpoint) != nullptr) && (mDeviceState(node, endpoint, cluster) == nullptr));
    ClusterState state{};
    state.clusterId       = cluster;
    state.clusterRevision = revision;
    VerifyOrDieWithSave(mDeviceState(node, endpoint)->clusters.emplace(cluster, state).second);
}

void fuzz::DeviceStateTracker::Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint32_t leaf, bool isCommand,
                                   std::optional<types::Access> commandAccess)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (cluster != kInvalidClusterId) && (leaf != kInvalidAttributeId));
    VerifyOrReturn(mDeviceState(node, endpoint, cluster) != nullptr);
    if (!isCommand)
    {
        VerifyOrReturn(ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, leaf) == nullptr);
        AttributeState state{};
        VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster)->attributes.emplace(leaf, state).second);
    }
    else
    {
        VerifyOrReturn(ReadValueOrNull(mDeviceState(node, endpoint, cluster)->serverCommands, leaf) == nullptr);
        VerifyOrDieWithSave(commandAccess.has_value());
        types::CommandSpecification serverCommand{ leaf, static_cast<uint16_t>(commandAccess.value()) };
        VerifyOrDieWithSave(mDeviceState(node, endpoint, cluster)->serverCommands.emplace(leaf, serverCommand).second);
    }
}

CHIP_ERROR fuzz::DeviceStateTracker::Load(YAML::Node & root, bool sync, FuzzingCommand * handler, bool partial,
                                          chip::app::ConcreteClusterPath clusterToLoad)
{
    if (partial)
    {
        VerifyOrReturnError(clusterToLoad.HasValidIds(), CHIP_ERROR_INVALID_ARGUMENT);
    }
    std::map<chip::app::ConcreteAttributePath, CHIP_ERROR> writeErrors;
    VerifyOrReturnError(root.IsMap() && root["state"], CHIP_ERROR_INVALID_ARGUMENT);
    for (const auto & node : root["state"])
    {
        VerifyOrReturnError(node.second.IsMap() && node.second["endpoints"], CHIP_ERROR_INVALID_ARGUMENT);
        Add(node.first.as<NodeId>());
        for (const auto & endpoint : node.second["endpoints"])
        {
            VerifyOrReturnError(endpoint.second.IsMap() && endpoint.second["clusters"] && endpoint.second["deviceTypes"],
                                CHIP_ERROR_INVALID_ARGUMENT);
            if (partial && endpoint.first.as<EndpointId>() != clusterToLoad.mEndpointId)
            {
                continue;
            }
            for (const auto & deviceType : endpoint.second["deviceTypes"])
            {
                VerifyOrReturnError(deviceType.IsMap() && deviceType["id"] && deviceType["revision"], CHIP_ERROR_INVALID_ARGUMENT);
                Add(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(),
                    DeviceTypeStruct{ deviceType["id"].as<DeviceTypeId>(), deviceType["revision"].as<uint16_t>() });
            }
            for (const auto & cluster : endpoint.second["clusters"])
            {
                if (partial && cluster.first.as<ClusterId>() != clusterToLoad.mClusterId)
                {
                    continue;
                }
                VerifyOrReturnError(cluster.second.IsMap() && cluster.second["attributes"] && cluster.second["revision"],
                                    CHIP_ERROR_INVALID_ARGUMENT);
                Add(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(), cluster.first.as<ClusterId>(),
                    cluster.second["revision"].as<uint16_t>());
                for (const auto & attrData : cluster.second["attributes"])
                {
                    VerifyOrReturnError(attrData.second.IsMap() && attrData.second["type"] && attrData.second["value"],
                                        CHIP_ERROR_INVALID_ARGUMENT);
                    types::AnyType value;
                    ReturnErrorOnFailure(utils::LoadAttribute(cluster.second["attributes"], attrData, value));
                    // If the sync flag is set to true, we synchronize the remote state with the local state.
                    if (sync)
                    {
                        chip::app::ConcreteAttributePath attrPath{ endpoint.first.as<EndpointId>(), cluster.first.as<ClusterId>(),
                                                                   attrData.first.as<AttributeId>() };
                        CHIP_ERROR status =
                            Sync(node.first.as<NodeId>(), attrPath, cluster.second["attributes"], attrData, value, handler);
                        // Synchronization fails when at least one attribute on the remote device state
                        // has a different value than the local one and the relative data model path does not support direct writes.
                        if (status != CHIP_NO_ERROR)
                        {
                            writeErrors.emplace(attrPath, status);
                        }
                    }
                    else
                    {
                        ReturnErrorOnFailure(WriteAttribute(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(),
                                                           cluster.first.as<ClusterId>(), attrData.first.as<AttributeId>(),
                                                           std::move(value)));
                    }
                }
            }
        }
    }

    if (sync)
    {
        bool hasErrors = !writeErrors.empty();
        for (const auto & [path, status] : writeErrors)
        {
            ChipLogError(chipToolFuzzing,
                         "Failed to synchronize path (0x%04" PRIX16 ", 0x%08" PRIX32 ", 0x%08" PRIX32 "). Error: 0x%08" PRIX32 "",
                         path.mEndpointId, path.mClusterId, path.mAttributeId, status.AsInteger());
        }
        if (hasErrors)
        {
            return CHIP_FUZZER_ERROR_REPLICATION_FAILED;
        }
    }
    return CHIP_NO_ERROR;
}

/*
 *  @brief Attempts synchronization of the remote state of an attribute using the data pointed by the `localAttrData` iterator.
 *  @return `CHIP_NO_ERROR` if the synchronization was successful or when the loaded and the remote value already match.
 *  `CHIP_FUZZER_ERROR_REPLICATION_FAILED` if the
 *  state could not be synchronized because of unsupported writes or insufficient write permissions.
 */
CHIP_ERROR fuzz::DeviceStateTracker::Sync(NodeId target, chip::app::ConcreteAttributePath & path, const YAML::Node & parent,
                                          const YAML::detail::iterator_value & localAttrData, types::AnyType & value,
                                          FuzzingCommand * handler)
{
    CHIP_ERROR status = CHIP_NO_ERROR;

    // 1. Read the remote attribute's value
    std::string readCommand = "any read-by-id " + std::to_string(path.mClusterId) + " " + std::to_string(path.mAttributeId) + " " +
        std::to_string(target) + " " + std::to_string(path.mEndpointId);

    types::AttributePathMap reportedValueMap;
    handler->ExecuteCommand(readCommand.c_str(), &status, &reportedValueMap);

    // 2. Check if the attribute was read successfully
    auto * reportedValue = ReadValueOrNull(reportedValueMap, path);
    VerifyOrReturnError(reportedValue && status == CHIP_NO_ERROR, CHIP_ERROR_INTERNAL);

    // 3. Compare the reported remote value with the one loaded from the YAML file
    // If the remote attribute's value is the same as the loaded, we skip the synchronization of that path
    if (Visitors::IsEqual(*reportedValue, value))
    {
        ChipLogDetail(chipToolFuzzing,
                      "Skipping synchronization of path (0x%04" PRIX16 ", 0x%08" PRIX32 ", 0x%08" PRIX32 ") as the values match.",
                      path.mEndpointId, path.mClusterId, path.mAttributeId);
        return CHIP_NO_ERROR;
    }

    // 4. Write the attribute's local value to the remote device
    std::string argValue;
    ReturnErrorOnFailure(utils::LoadAttributeAsArgument(parent, localAttrData, argValue));

    std::string writeCommand = "any write-by-id " + std::to_string(path.mClusterId) + " " + std::to_string(path.mAttributeId) +
        " " + argValue + " " + std::to_string(target) + " " + std::to_string(path.mEndpointId);

    handler->ExecuteCommand(writeCommand.c_str(), &status);
    return status;
}
size_t fuzz::DeviceStateTracker::GetTotalCommands()
{
    size_t totalCommands = 0;
    for (const auto & [nodeId, nodeState] : *List())
    {
        for (const auto & [endpointId, endpointState] : *List(nodeId))
        {
            for (const auto & [clusterId, clusterState] : *List(nodeId, endpointId))
            {
                auto commandListObj =
                    (*List(nodeId, endpointId, clusterId))[chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id]
                        .ReadCurrent();
                if (!std::holds_alternative<ContainerType>(commandListObj))
                {
                    continue;
                }
                auto commandList = std::get<ContainerType>(commandListObj);
                totalCommands += commandList.size();
            }
        }
    }
    return totalCommands;
}

size_t fuzz::DeviceStateTracker::GetTotalAttributes()
{
    size_t totalAttributes = 0;
    for (const auto & [nodeId, nodeState] : *List())
    {
        for (const auto & [endpointId, endpointState] : *List(nodeId))
        {
            for (const auto & [clusterId, clusterState] : *List(nodeId, endpointId))
            {
                auto attributeListObj =
                    (*List(nodeId, endpointId, clusterId))[chip::app::Clusters::Globals::Attributes::AttributeList::Id]
                        .ReadCurrent();
                if (!std::holds_alternative<ContainerType>(attributeListObj))
                {
                    continue;
                }
                auto attributeList = std::get<ContainerType>(attributeListObj);
                totalAttributes += attributeList.size();
            }
        }
    }
    return totalAttributes;
}
