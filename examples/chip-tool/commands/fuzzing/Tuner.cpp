#include "Tuner.h"
#include "Fuzzer.h"

bool fuzz::Tuner::IsMessageOrderCorrect()
{
    if (mMessageSequence.front() != MessageType::REQUEST)
        return false;
    MessageType last = mMessageSequence.front();
    for (auto message = mMessageSequence.begin(); message != mMessageSequence.end(); ++message)
    {
        if (*message < last)
            return false;
        last = *message;
    }
    return true;
}

bool fuzz::Tuner::Tune()
{
    mIssuedCommands++;
    if (!IsMessageOrderCorrect())
    {
        mConsecutiveCorrectSequences = 0;
        if (!mBackingOff)
        {
            ChipLogError(chipToolFuzzing, "***INCORRECT MESSAGE ORDER*** Backing off at %fms", mCurrentWaitingTime.count());
            mBackingOff = true;
        }
    }
    else if (IsMessageOrderCorrect() && mBackingOff)
        mConsecutiveCorrectSequences++;

    if (mBackingOff && (mIssuedCommands % mWaitingTimeGrowthCommandsInterval == 0))
    {
        // Waiting time increases by a factor of mWaitingTimeGrowthFactor
        mCurrentWaitingTime += mCurrentWaitingTime * mWaitingTimeGrowthFactor;
        ChipLogProgress(chipToolFuzzing, "Fine tuning report timeout at: %fms", mCurrentWaitingTime.count());
    }
    else if (!mBackingOff && (mIssuedCommands % mWaitingTimeShrinkCommandsInterval == 0))
    {
        // Waiting time decreases by a factor of mWaitingTimeShrinkFactor, limited to 250 ms
        mCurrentWaitingTime -= mCurrentWaitingTime * mWaitingTimeShrinkFactor;
        if (mCurrentWaitingTime < mMinWaitingTime)
        {
            mCurrentWaitingTime = mMinWaitingTime;
        }
        ChipLogProgress(chipToolFuzzing, "Fine tuning report timeout at: %fms", mCurrentWaitingTime.count());
    }

    mMessageSequence.clear();
    fuzz::Fuzzer::GetInstance()->GetContextManager()->SetReportTimeout(
        std::chrono::duration_cast<std::chrono::milliseconds>(mCurrentWaitingTime));
    return !IsTuned();
}
