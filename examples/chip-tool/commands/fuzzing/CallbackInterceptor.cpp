#include "CallbackInterceptor.h"
#include "Fuzzer.h"
#include "tlv/DecodedTLVElement.h"
#include "tlv/TLVDataPayloadHelper.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/InteractionModelEngine.h>
std::shared_ptr<types::AnyType> fuzz::CallbackInterceptor::ExtractCommandResponse(chip::TLV::TLVReader * data,
                                                                                  const chip::app::ConcreteCommandPath & path)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);
        VerifyOrDieWithSave(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        return std::make_shared<types::AnyType>(std::get<ContainerType>(output->content)[0]->content);
    }
    return nullptr;
}

std::shared_ptr<types::AnyType> fuzz::CallbackInterceptor::ExtractReportData(chip::TLV::TLVReader * data,
                                                                             const chip::app::ConcreteAttributePath & path)
{
    if (data != nullptr)
    {
        auto fuzzer = fuzz::Fuzzer::GetInstance();
        TLV::TLVDataPayloadHelper helper(data);

        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);
        VerifyOrDieWithSave(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);

        if (path.mClusterId == chip::app::Clusters::Descriptor::Id)
        {
            switch (path.mAttributeId)
            {
            case chip::app::Clusters::Descriptor::Attributes::PartsList::Id: {
                Visitors::TLV::ProcessDescriptorClusterResponse<EndpointId>(output, path, fuzzer->CurrentDestination());
                break;
            }
            case chip::app::Clusters::Descriptor::Attributes::DeviceTypeList::Id:
            case chip::app::Clusters::Descriptor::Attributes::ServerList::Id: {
                // This case also applies to the DeviceTypeId: both types are uint32_t
                Visitors::TLV::ProcessDescriptorClusterResponse<ClusterId>(output, path, fuzzer->CurrentDestination());
                break;
            }
            }
        }
        else if (path.mClusterId == chip::app::Clusters::BasicInformation::Id)
        {
            Visitors::TLV::ProcessBasicInformationClusterResponse(output, path, fuzzer->CurrentDestination());
        }
        else
        {
            auto & attributeState = fuzzer->GetDeviceStateTracker()->GetAttributeState(
                fuzzer->CurrentDestination(), path.mEndpointId, path.mClusterId, path.mAttributeId);
            helper.WriteToDeviceState(output, attributeState);
        }
        return std::make_shared<types::AnyType>(std::get<ContainerType>(output->content)[0]->content);
    }
    return nullptr;
}

std::shared_ptr<types::AnyType> fuzz::CallbackInterceptor::ExtractReportData(const chip::app::EventHeader & eventHeader,
                                                                             chip::TLV::TLVReader * data)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);
        VerifyOrDieWithSave(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        return std::make_shared<types::AnyType>(std::get<ContainerType>(output->content)[0]->content);
    }
    return nullptr;
}

void fuzz::CallbackInterceptor::AnalyzeReportError(const chip::app::ConcreteAttributePath & path)
{
    if (path.mClusterId == chip::app::Clusters::BasicInformation::Id || path.mClusterId == chip::app::Clusters::Descriptor::Id)
        return;

    auto fuzzer           = fuzz::Fuzzer::GetInstance();
    auto & attributeState = fuzzer->GetDeviceStateTracker()->GetAttributeState(fuzzer->CurrentDestination(), path.mEndpointId,
                                                                               path.mClusterId, path.mAttributeId);
    if (attributeState.IsReadable())
        attributeState.ToggleBlockReads();
}

void fuzz::CallbackInterceptor::AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                                                    CHIP_ERROR expectedError)
{}
