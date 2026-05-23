#include "InputGenerator.h"
#include "../DeviceStateTracker.h"
#include "../Fuzzer.h"
#include "../Visitors.h"
#include "../tlv/DecodedTLVElement.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <json/json.h>
#include <regex>
namespace {
uint64_t hexToUnsignedInt(const std::string & hexStr)
{
    uint64_t value;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> value;
    return value;
}

// Convert hex string to signed integer
int64_t hexToSignedInt(const std::string & hexStr)
{
    uint64_t unsignedValue = hexToUnsignedInt(hexStr);
    // Interpret the value as a signed integer based on its length
    int64_t signedValue = static_cast<int64_t>(unsignedValue);
    return signedValue;
}

// Convert hex string to float
float hexToFloat(const std::string & hexStr)
{
    uint32_t intValue = static_cast<uint32_t>(hexToUnsignedInt(hexStr));
    float floatValue;
    std::memcpy(&floatValue, &intValue, sizeof(floatValue)); // Bitwise conversion
    return floatValue;
}

// Convert hex string to double
double hexToDouble(const std::string & hexStr)
{
    uint64_t intValue = hexToUnsignedInt(hexStr);
    double doubleValue;
    std::memcpy(&doubleValue, &intValue, sizeof(doubleValue)); // Bitwise conversion
    return doubleValue;
}

// Function to scan and convert hex values in JSON string
std::string convertHexToDecimal(std::string json)
{
    // Define the regular expression pattern for matching the values
    std::regex pattern(R"(\"(s:|f:|d:)?(0x[0-9a-fA-F]+)\")");
    std::smatch match;

    std::string result;
    std::string::const_iterator searchStart(json.cbegin());

    while (std::regex_search(searchStart, json.cend(), match, pattern))
    {
        // Append the part of the JSON before the match
        result += match.prefix();

        // Extract the matched components
        std::string prefix   = match[1]; // "s:", "f:", "d:", or empty
        std::string hexValue = match[2]; // Hex number

        // Remove "0x" prefix from the hex number for easier conversion
        hexValue = hexValue.substr(2);

        // Convert based on the prefix
        std::ostringstream convertedValue;
        convertedValue << prefix;
        if (prefix == "s:")
        {
            convertedValue << hexToSignedInt(hexValue) << "\"";
        }
        else if (prefix == "f:")
        {
            convertedValue << std::fixed << hexToFloat(hexValue) << std::dec << "\"";
        }
        else if (prefix == "d:")
        {
            convertedValue << std::fixed << hexToDouble(hexValue) << std::dec << "\"";
        }
        else
        {
            convertedValue << hexToUnsignedInt(hexValue) << "\"";
        }

        // Append the converted value to the result
        result += "\"" + convertedValue.str();

        // Move searchStart forward to continue searching the rest of the string
        searchStart = match.suffix().first;
    }

    // Append the remaining part of the JSON string
    result += std::string(searchStart, json.cend());

    return result;
}
std::string collapseFieldIds(std::string json)
{
    std::regex pattern(R"(\"FIELD\":)");
    std::smatch match;
    std::string result;
    std::string::const_iterator searchStart(json.cbegin());
    int fieldId = 0;
    while (std::regex_search(searchStart, json.cend(), match, pattern))
    {
        result += match.prefix();
        result += "\"" + std::to_string(fieldId) + "\":";
        searchStart = match.suffix().first;
        fieldId++;
    }
    result += std::string(searchStart, json.cend());
    return result;
}
} // namespace
void gen::InputGenerator::CreateGrammar(DeviceStateTracker * deviceState, chip::NodeId node)
{
    VerifyOrReturn(!fs::exists(mpGeneratedLexerPath) && !fs::exists(mpGeneratedParserPath));

    std::ifstream baseLexerFile(mpBaseLexerPath);
    std::ifstream baseParserFile(mpBaseParserPath);
    VerifyOrDieWithMsg(baseLexerFile.is_open(), chipToolFuzzing, "Failed to open base lexer file.");
    VerifyOrDieWithMsg(baseParserFile.is_open(), chipToolFuzzing, "Failed to open base parser file.");

    std::ofstream generatedLexerFile(mpGeneratedLexerPath);
    VerifyOrDieWithMsg(generatedLexerFile.is_open(), chipToolFuzzing, "Failed to create lexer file.");
    std::string line;
    while (std::getline(baseLexerFile, line))
    {
        if (line.find("CommandLexer") != std::string::npos)
        {
            line.replace(line.find("CommandLexer"), std::string("CommandLexer").length(), GetLexerName());
        }
        generatedLexerFile << line << "\n";
    }

    std::unordered_map<chip::EndpointId, std::string> endpointTokens;
    std::unordered_map<chip::app::ConcreteClusterPath, std::string, types::MapKeyHasher> clusterTokens;

    auto endpoints = *deviceState->List(node);
    for (auto & endpoint : endpoints)
    {
        clusterTokens.clear();
        if (!endpoint.second.clusters.size())
            continue;

        std::string endpointToken = "'" + std::to_string(endpoint.first) + "' SPACE ";
        bool singleCluster        = endpoint.second.clusters.size() == 1;

        for (auto & cluster : endpoint.second.clusters)
        {
            auto attr = cluster.second.attributes.find(chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id);
            VerifyOrDieWithSave(attr != cluster.second.attributes.end());
            auto commandList = std::get<ContainerType>(attr->second.ReadCurrent());
            // Creating a token when the command list is empty would generate a token "'x' SPACE ()", which would be invalid.
            if (!commandList.size())
                continue;

            std::string clusterToken = "'" + std::to_string(cluster.first) + "' SPACE ";
            bool singleCommand       = commandList.size() == 1;

            VerifyOrDo(singleCommand, clusterToken += "(");
            for (size_t i = 0; i < commandList.size(); i++)
            {
                auto commandId = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(commandList[i]);
                clusterToken += "'" + std::to_string(commandId) + "'";
                if (i < commandList.size() - 1)
                {
                    clusterToken += "|";
                }
            }
            VerifyOrDo(singleCommand, clusterToken += ")");

            chip::app::ConcreteClusterPath clPath = { endpoint.first, cluster.first };
            clusterTokens[clPath]                 = clusterToken;
            generatedLexerFile << ("E" + std::to_string(endpoint.first) + "CL" + std::to_string(cluster.first) + ": " +
                                   clusterToken + ";\n");
        }
        if (!clusterTokens.size())
            continue;

        VerifyOrDo(singleCluster, endpointToken += "(");
        for (auto clToken = clusterTokens.begin(); clToken != clusterTokens.end(); clToken++)
        {
            endpointToken += "E" + std::to_string(clToken->first.mEndpointId) + "CL" + std::to_string(clToken->first.mClusterId);
            auto next = clToken;
            if (++next != clusterTokens.end())
            {
                endpointToken += "|";
            }
        }
        VerifyOrDo(singleCluster, endpointToken += ")");

        endpointTokens[endpoint.first] = endpointToken;
        generatedLexerFile << ("E" + std::to_string(endpoint.first) + ": " + endpointToken + ";\n");
    }
    bool singleEndpoint      = endpoints.size() == 1;
    std::string cmdPathToken = "";
    VerifyOrDo(singleEndpoint, cmdPathToken += "(");
    for (auto epToken = endpointTokens.begin(); epToken != endpointTokens.end(); epToken++)
    {
        cmdPathToken += "E" + std::to_string(epToken->first);
        auto next = epToken;
        if (++next != endpointTokens.end())
        {
            cmdPathToken += "|";
        }
    }
    VerifyOrDo(singleEndpoint, cmdPathToken += ")");

    generatedLexerFile << ("CMDPATH: " + cmdPathToken + ";\n");

    std::ofstream generatedParserFile(mpGeneratedParserPath);
    VerifyOrDieWithMsg(generatedParserFile.is_open(), chipToolFuzzing, "Failed to create parser file.");

    while (std::getline(baseParserFile, line))
    {
        if (line.find("CommandLexer") != std::string::npos)
        {
            line.replace(line.find("CommandLexer"), std::string("CommandLexer").length(), GetLexerName());
        }
        else if (line.find("CommandParser") != std::string::npos)
        {
            line.replace(line.find("CommandParser"), std::string("CommandParser").length(), GetParserName());
        }
        else if (line.find("}") != std::string::npos)
        {
            line = "}\n\nargs: CMDPATH SPACE payload EOF;";
        }
        generatedParserFile << line << "\n";
    }

    baseLexerFile.close();
    baseParserFile.close();
    generatedLexerFile.close();
    generatedParserFile.close();

    VerifyOrDieWithMsg(!generatedLexerFile.is_open(), chipToolFuzzing, "Lexer file was in an incorrect state.");
    VerifyOrDieWithMsg(!generatedParserFile.is_open(), chipToolFuzzing, "Parser file was in an incorrect state.");
    ChipLogProgress(chipToolFuzzing, "Grammar files generated successfully: GrammarID: %s.", mGrammarId.c_str());

    std::ostringstream processCommand(mPythonExecutable, std::ios_base::ate);
    std::string grammarinatorProcessFile = std::string(mEnvPrefix + "/bin/grammarinator-process");
    std::string baseLexerFilename        = mpBaseLexerPath.string();
    std::string baseParserFilename       = mpBaseParserPath.string();
    std::string generatedLexerFilename   = mpGeneratedLexerPath.string();
    std::string generatedParserFilename  = mpGeneratedParserPath.string();

    processCommand << " " << grammarinatorProcessFile << " " << generatedLexerFilename << " " << generatedParserFilename << " -o "
                   << mpGeneratedLexerPath.parent_path().string() << " --no-actions";

    VerifyOrDieWithMsg(std::system(processCommand.str().c_str()) == 0, chipToolFuzzing, "Failed to process grammar files.");
    ChipLogProgress(chipToolFuzzing, "Grammar files processed successfully.");
};

void gen::InputGenerator::SetPythonExecutable()
{
    VerifyOrDieWithMsg(std::system("python3 --version > /dev/null 2>&1") == 0, chipToolFuzzing,
                       "Python 3 is required to run the fuzzer.");
    fs::path execPath;
    if (const char * venvName = std::getenv("VIRTUAL_ENV"); venvName)
    {
        execPath = std::string(venvName) + "/bin/python3";
        ChipLogProgress(chipToolFuzzing, "Virtual environment '%s' detected. Using: %s", venvName, execPath.c_str());
        mEnvPrefix = venvName;
    }
    else if (const char * condaPrefix = std::getenv("CONDA_PREFIX"); condaPrefix)
    {
        execPath = std::string(condaPrefix) + "/bin/python3";
        ChipLogProgress(chipToolFuzzing, "Conda environment detected. Using: %s", execPath.c_str());
        mEnvPrefix = condaPrefix;
    }
    else
    {
        execPath = "python3";
        ChipLogProgress(chipToolFuzzing, "Using system Python");
        mEnvPrefix = "$PATH";
    }
    mPythonExecutable = execPath;
};

bool gen::InputGenerator::IsGrammarinatorInstalled()
{
    std::string command = mPythonExecutable + " -c \"import grammarinator\"";
    return std::system(command.c_str()) == 0;
}

void gen::InputGenerator::GenerateTestCases(fs::path pOutputFile, size_t numCases, uint16_t maxDepth)
{
    VerifyOrDieWithMsg(std::filesystem::exists(mpGeneratedLexerPath), chipToolFuzzing, "Lexer file not found.");
    VerifyOrDieWithMsg(std::filesystem::exists(mpGeneratedParserPath), chipToolFuzzing, "Parser file not found.");

    if (!fs::exists(pOutputFile.parent_path()))
    {
        VerifyOrDieWithSave(fs::create_directories(pOutputFile.parent_path()));
    }

    std::ostringstream command("PYTHONUNBUFFERED=1 " + mPythonExecutable, std::ios_base::ate);

    std::string grammarinatorGenerateFile = std::string(mEnvPrefix + "/bin/grammarinator-generate");
    std::string baseLexerFilename         = mpBaseLexerPath.string();
    std::string generatedLexerFilename    = mpGeneratedLexerPath.string();
    std::string generatorClassName        = std::string(mGrammarId + "_Generator." + mGrammarId + "_Generator");
    command << " " << grammarinatorGenerateFile << " " << generatorClassName << " -d " << maxDepth << " -n " << numCases
            << " -j 1 --stdout --sys-path " << mpGeneratedLexerPath.parent_path().string() << " > " << pOutputFile.string();

    ChipLogProgress(chipToolFuzzing, "Generating test cases...");
    VerifyOrDieWithMsg(std::system(command.str().c_str()) == 0, chipToolFuzzing, "Failed to generate test cases.");
    ChipLogProgress(chipToolFuzzing, "Generated %zu test cases.", numCases);
}

std::string gen::InputGenerator::ParseTestCase(chip::NodeId node, std::string testCase)
{
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::string errs;

    std::string endpoint, cluster, command;
    std::istringstream iss(testCase);

    // Skip the first three tokens (endpoint, cluster, command)
    iss >> endpoint >> cluster >> command;

    if (!Json::parseFromStream(reader, iss, &root, &errs))
    {
        std::cerr << "Error parsing JSON: " << errs << std::endl;
        return "";
    }

    // Serialize back to string without duplicate keys
    Json::StreamWriterBuilder writer;
    writer["indentation"]                  = "";
    std::string json                       = Json::writeString(writer, root);
    std::string payloadWithConvertedValues = convertHexToDecimal(json);
    std::string payload                    = collapseFieldIds(payloadWithConvertedValues);

    auto endpointId = static_cast<chip::EndpointId>(std::stoul(endpoint));
    auto clusterId  = static_cast<chip::ClusterId>(std::stoul(cluster));
    auto commandId  = static_cast<chip::CommandId>(std::stoul(command));

    if (fuzz::Fuzzer::GetInstance()->GetDeviceStateTracker()->CommandHasAccess(node, endpointId, clusterId, commandId,
                                                                               types::Access::kTimed))
        return cluster + " " + command + " " + payload + " " + std::to_string(node) + " " + endpoint +
            " --timedInteractionTimeoutMs 3000";
    else
        return cluster + " " + command + " " + payload + " " + std::to_string(node) + " " + endpoint;
}
