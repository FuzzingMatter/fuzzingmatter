#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include "Visitors.h"

namespace chip {
namespace fuzzing {

enum AttributeQualityEnum
{
    kNullable,
    kOptional,
    kMandatory,
};

struct AttributeWrapper
{
    AttributeWrapper(const AttributeWrapper & other)                 = default;
    AttributeWrapper(AttributeWrapper && other) noexcept             = default;
    AttributeWrapper & operator=(const AttributeWrapper & other)     = default;
    AttributeWrapper & operator=(AttributeWrapper && other) noexcept = default;

    AttributeWrapper(TLV::TLVType aType, uint8_t bytes = 0, AttributeQualityEnum aQuality = AttributeQualityEnum::kMandatory) :
        type(aType), quality(aQuality), length(bytes)
    {
        switch (quality)
        {
        case AttributeQualityEnum::kMandatory:
            value = types::AnyType{};
            break;
        case AttributeQualityEnum::kOptional:
            value = chip::Optional<types::AnyType>::Missing();
            break;
        default:
            break;
        }
    }
    AttributeWrapper(TLV::TLVType aType, types::AnyType && aValue, uint8_t bytes = 0,
                     AttributeQualityEnum aQuality = AttributeQualityEnum::kMandatory) :
        type(aType), quality(aQuality), length(bytes)
    {
        switch (quality)
        {
        case AttributeQualityEnum::kMandatory:
            value = types::AnyType{};
            break;
        case AttributeQualityEnum::kOptional:
            value = chip::Optional<types::AnyType>::Missing();
            break;
        default:
            return;
        }
        Write(std::move(aValue));
    }
    TLV::TLVType type;
    AttributeQualityEnum quality;
    uint8_t length;
    uint16_t access = static_cast<uint16_t>(types::Access::kRead) | static_cast<uint16_t>(types::Access::kWrite);
    // TODO: Add support for nullable attributes
    std::variant<std::monostate, types::AnyType, chip::Optional<types::AnyType>> value = {};

    const types::AnyType & Read() { return Visitors::AttributeWrapperRead(this); }
    CHIP_ERROR Write(types::AnyType && aValue)
    {
        size_t typeIndexBeforeWrite           = value.index();
        size_t underlyingTypeIndexBeforeWrite = Read().index();
        size_t typeIndexAfterWrite            = UINT64_MAX;
        size_t underlyingTypeIndexAfterWrite  = UINT64_MAX;

        ReturnErrorOnFailure(
            Visitors::AttributeWrapperWriteOrFail(this, typeIndexAfterWrite, underlyingTypeIndexAfterWrite, std::move(aValue)));
        VerifyOrReturnError(typeIndexAfterWrite != UINT64_MAX && underlyingTypeIndexAfterWrite != UINT64_MAX, CHIP_ERROR_INTERNAL);

        /**
         * AttributeWrapper value type must remain identical, but underlying value type can change if and only if the value is
         * being set for the first time. The only type change permitted is from std::monostate (uninitialized) to another type.
         */
        VerifyOrReturnError(typeIndexBeforeWrite == 0 || typeIndexBeforeWrite == typeIndexAfterWrite,
                            CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH);
        VerifyOrReturnError(underlyingTypeIndexBeforeWrite == 0 || underlyingTypeIndexBeforeWrite != underlyingTypeIndexAfterWrite,
                            CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH);
        return CHIP_NO_ERROR;
    }
};

/**
 * @brief Factory class to create AttributeWrapper instances.
 *
 * The AttributeWrapper creation follows these steps:
 *
 * 1. Call the static Create method with the type, value, length and quality. This method firstly checks if given arguments are
 * supported.
 *
 * 2. If arguments are supported, TrySetAttribute is called to create the AttributeWrapper instance.
 *
 * 3. To set the attribute value, which can be either of type std::monostate (uninitialized), AnyType (mandatory) or
 * chip::Optional<AnyType>> (optional), the visitor inside TrySetAttribute checks which type of variant is being holded by the
 * argument value and, based on the quality, sets the value.
 *
 * 4. A unique_ptr to the AttributeWrapper instance is returned.
 *
 */
struct AttributeFactory
{
public:
    static std::shared_ptr<AttributeWrapper> Create(TLV::TLVType type, types::AnyType && value, uint8_t length = 0,
                                                    AttributeQualityEnum quality = AttributeQualityEnum::kMandatory);

    static std::shared_ptr<AttributeWrapper> Create(TLV::TLVType type, uint8_t length = 0,
                                                    AttributeQualityEnum quality = AttributeQualityEnum::kMandatory)
    {
        return Create(type, types::AnyType{}, length, quality);
    };
};

} // namespace fuzzing
} // namespace chip
