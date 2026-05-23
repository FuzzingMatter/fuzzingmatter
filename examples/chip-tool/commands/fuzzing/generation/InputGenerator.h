#pragma once
#include "../DeviceStateTracker.h"
#include "../ForwardDeclarations.h"
#include <fstream>

namespace chip {
namespace fuzzing {
namespace generation {

class InputGenerator
{
public:
    InputGenerator(const chip::fuzzing::BasicInformation * nodeInfo, fs::path pBaseDirectory) :
        mpBaseLexerPath(std::string(std::getenv("PW_PROJECT_ROOT")) + "/generation/CommandLexer.g4"),
        mpBaseParserPath(std::string(std::getenv("PW_PROJECT_ROOT")) + "/generation/CommandParser.g4")
    {

        if (!fs::exists(pBaseDirectory))
        {
            VerifyOrDie(fs::create_directories(pBaseDirectory));
        }
        mGrammarId       = nodeInfo->ToString();
        mpTargetDataPath = pBaseDirectory;
        if (!fs::exists(mpTargetDataPath))
        {
            VerifyOrDie(fs::create_directories(mpTargetDataPath));
        }

        mpGeneratedLexerPath  = mpTargetDataPath / (mGrammarId + "_Lexer.g4");
        mpGeneratedParserPath = mpTargetDataPath / (mGrammarId + "_Parser.g4");
        SetPythonExecutable();
        VerifyOrDieWithMsg(IsGrammarinatorInstalled(), chipToolFuzzing,
                           "Python package 'grammarinator' is required for fuzzer grammar generation.");
    };
    ~InputGenerator() {};

    std::string mGrammarId;

    void CreateGrammar(DeviceStateTracker * deviceState, chip::NodeId node);
    void GenerateTestCases(fs::path apOutputDirectory, size_t numCases, uint16_t maxDepth = 32);
    // Removes duplicate keys from the test case payload and converts all keys from hex to decimal.
    static std::string ParseTestCase(chip::NodeId node, std::string testCase);

private:
    fs::path mpBaseLexerPath;
    fs::path mpBaseParserPath;
    fs::path mpGeneratedLexerPath;
    fs::path mpGeneratedParserPath;
    fs::path mpTargetDataPath;
    std::string mPythonExecutable;
    std::string mEnvPrefix;

    std::string GetLexerName() { return mpGeneratedLexerPath.stem().string(); }
    std::string GetParserName() { return mpGeneratedParserPath.stem().string(); }
    void SetPythonExecutable();
    bool IsGrammarinatorInstalled();
};

} // namespace generation
} // namespace fuzzing
} // namespace chip
