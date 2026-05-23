#pragma once
#include "ForwardDeclarations.h"
namespace chip {
namespace fuzzing {

class Tuner
{
public:
    Tuner(uint16_t minWaiting, double shrinkFactor, uint16_t shrinkCommandsInterval, double growthFactor,
          uint16_t growthCommandsInterval) :
        mMinWaitingTime(minWaiting), mWaitingTimeShrinkFactor(shrinkFactor),
        mWaitingTimeShrinkCommandsInterval(shrinkCommandsInterval), mWaitingTimeGrowthFactor(growthFactor),
        mWaitingTimeGrowthCommandsInterval(growthCommandsInterval), mConsecutiveCorrectSequencesLimit(growthCommandsInterval * 10)
    {}

    enum MessageType
    {
        REQUEST,
        RESPONSE,
        REPORT
    };

    bool IsMessageOrderCorrect();
    void AddMessage(MessageType message) { mMessageSequence.push_back(message); }
    bool Tune();

    auto GetCurrentWaitingTime() { return mCurrentWaitingTime.count(); }

private:
    bool mBackingOff         = false;
    uint64_t mIssuedCommands = 0;
    std::chrono::duration<double, std::milli> mCurrentWaitingTime{ 3000 };
    std::vector<MessageType> mMessageSequence;
    // Number of consecutive times the message order was correct
    // Number of correct message sequences required to stop tuning while in backoff
    std::chrono::milliseconds mMinWaitingTime;
    double mWaitingTimeShrinkFactor;
    uint16_t mWaitingTimeShrinkCommandsInterval;
    double mWaitingTimeGrowthFactor;
    uint16_t mWaitingTimeGrowthCommandsInterval;
    uint64_t mConsecutiveCorrectSequences = 0;
    uint16_t mConsecutiveCorrectSequencesLimit;
    bool IsTuned() { return mConsecutiveCorrectSequences >= mConsecutiveCorrectSequencesLimit; }
};
} // namespace fuzzing
} // namespace chip
