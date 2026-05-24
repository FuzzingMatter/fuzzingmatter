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
            auto wrapper = std::make_shared<AttributeWrapper>(type, length, quality);
            ReturnValueOnFailure(wrapper->Write(std::move(value)), nullptr);
            return wrapper;
        }
    }
    return nullptr; // Default factory logic
};
