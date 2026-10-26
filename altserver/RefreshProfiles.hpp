// Profile-only renewal uses AltSign's existing Apple API, as AltStore does.
// It never creates/revokes certificates, changes App IDs, signs, or installs an IPA.
#pragma once
#include <fstream>
#include <algorithm>
#include <cctype>
#include "AppleAPI.hpp"
#include "AnisetteDataManager.h"

inline std::string RefreshSerial(std::string value)
{
    value.erase(std::remove(value.begin(), value.end(), ':'), value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::toupper(c); });
    auto first = value.find_first_not_of('0');
    return first == std::string::npos ? "0" : value.substr(first);
}

inline int RefreshProfiles(const char *requestPath, const char *appleID, const char *password)
{
    bool authenticating = false;
    try {
        std::ifstream input(requestPath);
        auto request = web::json::value::parse(input);
        auto teamID = request.at("team").as_string();
        auto output = request.at("output").as_string();
        auto serial = RefreshSerial(request.at("certificate_serial").as_string());
        auto bundles = request.at("bundles").as_array();
        if (teamID.empty() || output.empty() || bundles.size() == 0 || bundles.size() > 128)
            throw std::runtime_error("invalid request");
        auto handler = []() -> pplx::task<std::optional<std::string>> {
            return pplx::create_task([]() -> std::optional<std::string> {
                std::cout << "Enter two factor code" << std::endl;
                std::string code;
                if (!(std::cin >> code)) return std::nullopt;
                return code;
            });
        };
        auto api = AppleAPI::getInstance();
        authenticating = true;
        auto auth = api->Authenticate(appleID, password,
            AnisetteDataManager::instance()->FetchAnisetteData(), handler).get();
        authenticating = false;
        std::shared_ptr<Team> team;
        for (auto candidate : api->FetchTeams(auth.first, auth.second).get())
            if (candidate->identifier() == teamID) team = candidate;
        if (!team) {
            std::cerr << "Renewal requires repair: the installed app belongs to a different signing team." << std::endl;
            return 42;
        }
        bool certificatePresent = false;
        for (auto certificate : api->FetchCertificates(team, auth.second).get())
            if (RefreshSerial(certificate->serialNumber()) == serial) certificatePresent = true;
        if (!certificatePresent) {
            std::cerr << "Renewal requires repair: the installed signing certificate is no longer available." << std::endl;
            return 42;
        }
        auto appIDs = api->FetchAppIDs(team, auth.second).get();
        std::vector<std::shared_ptr<AppID>> selected;
        for (auto value : bundles) {
            auto bundle = value.as_string();
            std::shared_ptr<AppID> found;
            for (auto candidate : appIDs)
                if (candidate->bundleIdentifier() == bundle) found = candidate;
            if (!found) {
                std::cerr << "Renewal requires repair: an installed App ID is no longer available." << std::endl;
                return 42;
            }
            selected.push_back(found);
        }
        std::cout << "Fetching renewal profiles..." << std::endl;
        for (size_t i = 0; i < selected.size(); ++i) {
            auto profile = api->FetchProvisioningProfile(selected[i], Device::Type::iPhone, team, auth.second).get();
            auto data = profile->data();
            std::ofstream file(output + "/" + std::to_string(i) + ".mobileprovision", std::ios::binary);
            file.write(reinterpret_cast<const char *>(data.data()), data.size());
            file.close();
            if (!file) throw std::runtime_error("profile output failed");
        }
        std::cout << "Renewal profiles fetched." << std::endl;
        return 0;
    } catch (Error& error) {
        if (authenticating) std::cerr << "Apple account authentication failed." << std::endl;
        std::cerr << "Error: " << error.domain() << " (" << error.code() << ")." << std::endl;
    } catch (std::exception&) {
        if (authenticating) std::cerr << "Apple account authentication failed." << std::endl;
        std::cerr << "Profile renewal could not complete; no app was installed." << std::endl;
    }
    return 1;
}
