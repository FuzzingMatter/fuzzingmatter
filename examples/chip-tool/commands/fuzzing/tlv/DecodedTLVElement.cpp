#include "DecodedTLVElement.h"
#include "../Fuzzer.h"
void TLV::DecodedTLVElementPrettyPrinter::Print()
{
    VerifyOrDieWithSave(mRootElement != nullptr);
    Visitors::TLV::PrintDecodedElement(this, mRootElement, 0);
}

void TLV::DecodedTLVElementPrettyPrinter::PrintDecodedElementMetadata(std::shared_ptr<TLV::DecodedTLVElement> element,
                                                                      size_t indent)
{
    VerifyOrDieWithSave(element != nullptr);
    fuzz::Indent(indent);
    std::cout << "[Type: 0x" << std::hex << static_cast<int16_t>(element->type) << std::dec
              << ", Byte size: " << static_cast<uint16_t>(element->length) << ", Tag: 0x" << std::hex
              << static_cast<int16_t>(element->tag) << " (" << std::dec
              << (element->quality == fuzz::AttributeQualityEnum::kMandatory ? "mandatory" : "optional");
    Visitors::TLV::FinalizePrintDecodedElementMetadata(this, element, indent);
}
