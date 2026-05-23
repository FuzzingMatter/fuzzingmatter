#include "Utils.h"
#include "tlv/DecodedTLVElement.h"
#include <iostream>
#include <sys/ioctl.h>

namespace {
template <typename T>
bool SafeStringToTyped(const std::string & str, types::AnyType & value);

template <>
bool SafeStringToTyped<char *>(const std::string & str, types::AnyType & value)
{
    char * out;
    std::istringstream ss(str);
    if (str.substr(0, 4) == "hex:")
    {
        std::string tmp;
        ss.ignore(4);
        ss >> std::hex >> tmp;
        out = new char[tmp.size() / 2];

        // Convert every pair of hex chars in the string to a byte
        for (size_t i = 0; i < tmp.size(); i += 2)
            out[i / 2] = static_cast<char>(std::stoi(tmp.substr(i, 2), nullptr, 16));
    }
    else
        return false;

    VerifyOrReturnValue(!ss.fail(), false);
    value = out;
    return true;
}

template <typename T>
bool SafeStringToTyped(const std::string & str, types::AnyType & value)
{
    T out;
    std::istringstream ss(str);
    if (str.substr(0, 2) == "s:" && std::is_same_v<T, int64_t>)
    {
        ss.ignore(2);
        ss >> out;
    }
    else if (str.substr(0, 2) == "f:" && std::is_same_v<T, float>)
    {
        ss.ignore(2);
        ss >> out;
    }
    else if (str.substr(0, 2) == "d:" && std::is_same_v<T, double>)
    {
        ss.ignore(2);
        ss >> out;
    }
    else
        ss >> out;

    VerifyOrReturnValue(!ss.fail(), false);
    value = out;
    return true;
}

// TODO: Useful when type is nullable but value is not null
CHIP_ERROR AttemptAttributeConversionFromValue(const YAML::Node & attribute, types::AnyType & value, std::string & convertedType)
{
    if (attribute["value"].IsSequence() || attribute["value"].IsMap())
    {
        auto container     = fuzz::ContainerType{};
        auto nestedElement = std::make_shared<fuzz::TLV::DecodedTLVElement>();
        for (const auto & field : attribute["value"])
        {
            auto nestedValue = attribute["value"].IsSequence() ? field : field.second;
            VerifyOrReturnError(CHIP_NO_ERROR ==
                                    AttemptAttributeConversionFromValue(nestedValue, nestedElement->content, convertedType),
                                CHIP_ERROR_INTERNAL);
            container.push_back(nestedElement);
        }
        value = container;
        return CHIP_NO_ERROR;
    }
    else
    {
        std::string parsedValue = attribute["value"].as<std::string>("undefined");
        VerifyOrReturnError(parsedValue != "undefined", CHIP_ERROR_INTERNAL);
        // We assign the upcoming attempted type, so that if the conversion succeeds the function returns after setting the right
        // type.
        convertedType = "uint8";
        VerifyOrReturnError(!SafeStringToTyped<uint8_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "int8";
        VerifyOrReturnError(!SafeStringToTyped<int8_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "uint16";
        VerifyOrReturnError(!SafeStringToTyped<uint16_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "int16";
        VerifyOrReturnError(!SafeStringToTyped<int16_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "uint32";
        VerifyOrReturnError(!SafeStringToTyped<uint32_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "int32";
        VerifyOrReturnError(!SafeStringToTyped<int32_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "uint64";
        VerifyOrReturnError(!SafeStringToTyped<uint64_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "int64";
        VerifyOrReturnError(!SafeStringToTyped<int64_t>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "float";
        VerifyOrReturnError(!SafeStringToTyped<float>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "double";
        VerifyOrReturnError(!SafeStringToTyped<double>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "boolean";
        VerifyOrReturnError(!SafeStringToTyped<bool>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "bytes";
        VerifyOrReturnError(!SafeStringToTyped<char *>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "string";
        VerifyOrReturnError(!SafeStringToTyped<std::string>(parsedValue, value), CHIP_NO_ERROR);
        convertedType = "undefined";
    }
    return CHIP_ERROR_INTERNAL;
}

} // namespace

void fuzz::Indent(size_t indent)
{
    for (size_t i = 0; i < indent; i++)
    {
        std::cout << " ";
    }
}

std::string fuzz::GetElapsedTime(std::chrono::steady_clock::time_point startTime)
{
    auto now     = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();

    int64_t hours   = elapsed / 3600;
    int64_t minutes = (elapsed % 3600) / 60;
    int64_t seconds = elapsed % 60;

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hours << ":" << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << seconds;

    return oss.str();
}

bool fuzz::IsManufacturerSpecificTestingCluster(ClusterId cluster)
{
    /**
     * Standard clusters are in range 0x0000_0000 - 0x0007_FFFF.
     * Manufacturer-specific clusters are in range 0x0001_XXXX - 0xFFF4_YYYY, where XXXX >= FC00 and YYYY <= FFFE.
     * Valid mnufacturer-specific clusters IDs ranging from 0xFFF1_0000 to 0xFFF4_FFFE are reserved to testing.
     */
    uint32_t manufacturerCode        = cluster & 0xFFFF0000;
    uint32_t manufacturerProductCode = cluster & 0x0000FFFE;
    return manufacturerCode >= 0xFFF10000 && manufacturerCode <= 0xFFF4FFFE && manufacturerProductCode >= 0xFC00;
}

void utils::DefaultValuesGenerator::AddDefaultValueToPayload(Json::Value & payload, std::string id, chip::TLV::TLVType type,
                                                             uint8_t size)
{
    switch (type)
    {
    case chip::TLV::TLVType::kTLVType_List:
    case chip::TLV::TLVType::kTLVType_Array: {
        payload[id] = Json::Value(Json::arrayValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Structure: {
        payload[id] = Json::Value(Json::objectValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Null: {
        payload[id] = Json::Value(Json::nullValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Boolean: {
        payload[id] = false;
        break;
    }
    default: {
        payload[id] = GetDefaultValue({ type, size });
        break;
    }
    }
}

CHIP_ERROR utils::LoadAttribute(const YAML::Node & parent, const YAML::detail::iterator_value & node, types::AnyType & value)
{
    // node.second only exists when the node is a member of a map.
    auto attribute = parent.IsSequence() ? node : node.second;
    bool failed    = false;
    std::string convertedType;

    // clang-format off
    const std::unordered_map<std::string, std::function<void()>> conversionMap = {
        { "boolean",    [&]() { value = attribute["value"].as<bool>(); } },
        { "string",     [&]() { value = attribute["value"].as<std::string>(); } },
        { "uint8",      [&]() { value = attribute["value"].as<uint8_t>(); } },
        { "uint16",     [&]() { value = attribute["value"].as<uint16_t>(); } },
        { "uint32",     [&]() { value = attribute["value"].as<uint32_t>(); } },
        { "uint64",     [&]() { value = attribute["value"].as<uint64_t>(); } },
        { "int8",       [&]() { value = attribute["value"].as<int8_t>(); } },
        { "int16",      [&]() { value = attribute["value"].as<int16_t>(); } },
        { "int32",      [&]() { value = attribute["value"].as<int32_t>(); } },
        { "int64",      [&]() { value = attribute["value"].as<int64_t>(); } },
        { "float",      [&]() { value = attribute["value"].as<float>(); } },
        { "double",     [&]() { value = attribute["value"].as<double>(); } },
        { "nullable",   
          [&]() { 
            if (attribute["value"].as<std::string>() == "null")
                value = chip::NullOptional;
            else {
                failed = CHIP_NO_ERROR != AttemptAttributeConversionFromValue(attribute["value"], value, convertedType);
            }} },
        { "bytes",
          [&]() {
              char * byteString = new char[attribute["value"].as<std::string>().size() + 1];
              std::strcpy(byteString, attribute["value"].as<std::string>().c_str());
              value = byteString;
          } },
        { "container",
          [&]() {
              fuzz::ContainerType container{};
              for (const auto & element : attribute["value"])
              {
                auto nestedElement = std::make_shared<fuzz::TLV::DecodedTLVElement>();
                failed = CHIP_NO_ERROR != LoadAttribute(attribute["value"], element, nestedElement->content);
                container.push_back(std::move(nestedElement));
              }
              value = container;
          } }
    };
    // clang-format on

    if (conversionMap.find(attribute["type"].as<std::string>()) == conversionMap.end())
    {
        return CHIP_ERROR_INTERNAL;
    }
    conversionMap.at(attribute["type"].as<std::string>())();

    if (failed)
        return CHIP_ERROR_INTERNAL;
    return CHIP_NO_ERROR;
}

CHIP_ERROR utils::LoadAttributeAsArgument(const YAML::Node & parent, const YAML::detail::iterator_value & node, std::string & arg)
{
    auto attribute = parent.IsSequence() ? node : node.second;

    auto writeContainer = [&](auto self, const std::unordered_map<std::string, std::function<std::string()>> * map,
                              const YAML::Node & container) -> std::string {
        Json::Value convertedContainer = Json::Value(Json::arrayValue);
        for (const auto & element : container)
        {
            auto currentElement     = container.IsSequence() ? element : element.second;
            std::string elementType = currentElement["type"].as<std::string>();
            if (elementType == "container")
            {
                convertedContainer.append(self(self, map, currentElement["value"]));
            }
            else
            {
                convertedContainer.append(map->at(elementType)());
            }
        }
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        return Json::writeString(builder, convertedContainer);
    };
    // clang-format off
    const std::unordered_map<std::string, std::function<std::string()>> conversionMap = {
        { "boolean",    [&]() { return attribute["value"].as<std::string>(); } },
        { "string",     [&]() { return attribute["value"].as<std::string>(); } },
        { "uint8",      [&]() { return attribute["value"].as<std::string>(); } },
        { "uint16",     [&]() { return attribute["value"].as<std::string>(); } },
        { "uint32",     [&]() { return attribute["value"].as<std::string>(); } },
        { "uint64",     [&]() { return attribute["value"].as<std::string>(); } },
        { "int8",       [&]() { return "s:" + attribute["value"].as<std::string>(); } },
        { "int16",      [&]() { return "s:" + attribute["value"].as<std::string>(); } },
        { "int32",      [&]() { return "s:" + attribute["value"].as<std::string>(); } },
        { "int64",      [&]() { return "s:" + attribute["value"].as<std::string>(); } },
        { "float",      [&]() { return "f:" + attribute["value"].as<std::string>(); } },
        { "double",     [&]() { return "d:" + attribute["value"].as<std::string>(); } },
        { "bytes",      [&]() { return "hex:" + attribute["value"].as<std::string>(); } },
        { "nullable",   
          [&]() { 
            // Attribute may be of nullable type but still have a typed value
            return (attribute["value"].IsSequence() || attribute["value"].IsMap()) ? 
                writeContainer(writeContainer, &conversionMap, attribute["value"]) : attribute["value"].as<std::string>(); 
            } 
        },
        { "container",  [&]() { return writeContainer(writeContainer, &conversionMap, attribute["value"]); } }
    };
    // clang-format on

    if (conversionMap.find(attribute["type"].as<std::string>()) == conversionMap.end())
    {
        return CHIP_ERROR_INTERNAL;
    }
    arg = conversionMap.at(attribute["type"].as<std::string>())();

    return CHIP_NO_ERROR;
}

bool types::MapKeyEqualizer::AreReportedDataAttributePathsEqual(const AttributePathMap & m0, const AttributePathMap & m1) const
{
    if (m0.size() != m1.size())
    {
        return false;
    }

    for (auto & [k, _] : m0)
    {
        if (m1.find(k) == m1.end())
        {
            return false;
        }
    }
    return true;
};

bool types::MapKeyEqualizer::IsResponseDataEqual(const std::shared_ptr<AnyType> v0, const std::shared_ptr<AnyType> v1) const
{
    if (v0 && v1)
        return fuzz::Visitors::IsEqual(*v0, *v1);
    else if (!v0 && !v1)
        return true;
    else
        return false;
}
