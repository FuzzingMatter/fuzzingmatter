#include "Fuzzer.h"
void fuzz::Fuzzer::SetOutputLogger(BasicInformation nodeInfo, fs::path outputDirectory)
{
    mOutputLogger = new fuzz::OutputLogger(nodeInfo, mTarget, outputDirectory / nodeInfo.ToString() / "results", mStartTime);
}
