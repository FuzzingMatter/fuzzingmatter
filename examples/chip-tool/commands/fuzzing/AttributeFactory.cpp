#include "AttributeFactory.h"
#include "Fuzzer.h"
std::shared_ptr<fuzz::AttributeWrapper> fuzz::AttributeFactory::Create(TLV::TLVType type, types::AnyType && value, uint8_t length,
                                                                       AttributeQualityEnum quality)
{
    VerifyOrDieWithSave(quality != AttributeQualityEnum::kNullable);
    auto key = std::make_pair(type, length);
    for (const auto & supportedType : supportedTypes)
    {
        if (supportedType == key)
        {
            return std::make_shared<AttributeWrapper>(type, std::move(value), length, quality);
        }
    }
    return nullptr; // Default factory logic
};
