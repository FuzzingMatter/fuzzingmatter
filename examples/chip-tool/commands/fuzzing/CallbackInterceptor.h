#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <app/EventHeader.h>
namespace chip {
namespace fuzzing {
class CallbackInterceptor
{
public:
    CallbackInterceptor() {}
    // Analyzes data coming from the ClusterCommand::OnResponse callback.
    std::shared_ptr<types::AnyType> ExtractCommandResponse(chip::TLV::TLVReader * data,
                                                           const chip::app::ConcreteCommandPath & path);

    // Analyzes data coming from the ReportCommand::OnAttributeData and WriteAttributeCommand::OnResponse callbacks.
    std::shared_ptr<types::AnyType> ExtractReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteAttributePath & path);

    // Analyzes data coming from the ReportCommand::OnEventData callback.
    std::shared_ptr<types::AnyType> ExtractReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data);

    /**
     * Analyzes a recoverable error occurred while reporting, i.e. errors on single attributes in a transaction that involves
     * multiple ones. Currently it is only used when a read operation on an attribute with manufacturer-specific default value
     * conformance is done. In such case, the attribute value is uninitialized and it needs to be written at least once before
     * attempting a successful read.
     */
    void AnalyzeReportError(const chip::app::ConcreteAttributePath & path);

    // Analyzes data coming from the OnError callbacks.
    void AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                             CHIP_ERROR expectedError = CHIP_NO_ERROR);
};

} // namespace fuzzing
} // namespace chip
