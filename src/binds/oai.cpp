#include "bindings.h"
#include "liboai.h"

// todo ...
// https://github.com/D7EAD/liboai/blob/main/documentation/chat/examples/create_chat_completion_async.cpp

using namespace liboai;

const char *get_api_key() {
    const char *key = getenv("OPENAI_API_KEY");
    if (key == nullptr) {
        console->error("OPENAI_API_KEY not found");
        std::string key;
        std::cout << "Please input your OpenAI API Key: ";
        std::cin >> key;
        return key.c_str();
    }
    return key;
}

void test_curl() {

    curl_global_init(CURL_GLOBAL_ALL);

    CURL *curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com");
        std::string response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void *contents, size_t size, size_t nmemb, std::string *output) {
            size_t total_size = size * nmemb;
            output->append((char *)contents, total_size);
            return total_size;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            std::cout << "Response:\n"
                      << response << std::endl;
        }

        curl_easy_cleanup(curl);
    }
}

int test_oai() {
    OpenAI oai;
    oai.auth.SetKeyEnv(get_api_key());

    liboai::FutureResponse create_async(
        const std::string &model,
        const Conversation &conversation,
        std::optional<float> temperature = std::nullopt,
        std::optional<float> top_p = std::nullopt,
        std::optional<uint16_t> n = std::nullopt,
        std::optional<std::function<bool(std::string, intptr_t)>> stream = std::nullopt,
        std::optional<std::vector<std::string>> stop = std::nullopt,
        std::optional<uint16_t> max_tokens = std::nullopt,
        std::optional<float> presence_penalty = std::nullopt,
        std::optional<float> frequency_penalty = std::nullopt,
        std::optional<std::unordered_map<std::string, int8_t>> logit_bias = std::nullopt,
        std::optional<std::string> user = std::nullopt);
}

int test_chat() {
    OpenAI oai;

    Conversation convo;

    convo.AddUserData("What is the point of taxes?");
    if (oai.auth.SetKeyEnv(get_api_key())) {
        try {
            auto fut = oai.ChatCompletion->create_async(
                "gpt-3.5-turbo", convo);

            // do other work...

            // check if the future is ready
            fut.wait();

            // get the contained response
            auto response = fut.get();

            // update our conversation with the response
            convo.Update(response);

            // print the response
            std::cout << convo.GetLastResponse() << std::endl;
        } catch (std::exception &e) {
            std::cout << e.what() << std::endl;
        }
    }
}

void chat(const char *msg) {
    printf("%s\n", msg);
    test_chat();
}

BINDFUNC(oai) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("oai")
        .addFunction("chat", &chat)
        .endNamespace()
        .beginNamespace("curl")
        .addFunction("test", &test_curl)
        .endNamespace();
}