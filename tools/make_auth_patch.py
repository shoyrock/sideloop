"""Generate the small AltServer entrypoint patch from the pinned source checkout."""
import difflib
import sys
from pathlib import Path

source = Path(sys.argv[1]) / 'src/AltServerMain.cpp'
old = source.read_text().replace('\r\n', '\n')
new = old.replace('#include "Error.hpp"', '#include "Error.hpp"\n#include "AppleAPI.hpp"\n#include "AnisetteDataManager.h"')
new = new.replace('{"debug",', '{"verify-account", no_argument, 0, \'v\'},\n\t\t  {"debug",')
new = new.replace('char *appleID;', 'char *appleID = nullptr;').replace('char *password;', 'char *password = nullptr;')
new = new.replace('int debugLogLevel = 0;', 'int debugLogLevel = 0;\n\tbool verifyAccount = false;')
new = new.replace('"u:i:a:p:P:d"', '"u:i:a:p:P:dv"')
new = new.replace("\t\t\tappleID = optarg;", "\t\t\tappleID = optarg;\n\t\t\tbreak;")
new = new.replace("case 'd':", "case 'v':\n\t\t\tverifyAccount = true;\n\t\t\tbreak;\n\t\tcase 'd':")
new = new.replace('"  -d  --debug', '"      --verify-account  Authenticate without signing or installing an app.\\n"\n\t\t\t"  -d  --debug')
new = new.replace('if (optind == argc) {', 'if (verifyAccount) {\n\t\tif (!appleID) appleID = getenv("ALTSERVER_APPLE_ID");\n\t\tif (!password) password = getenv("ALTSERVER_APPLE_PASSWORD");\n\t\tif (!appleID || !password || optind != argc) {\n\t\t\tstd::cerr << "Account verification needs Apple ID and password, without an IPA." << std::endl;\n\t\t\treturn 1;\n\t\t}\n\t\tinstallApp = false;\n\t} else if (optind == argc) {')
verification = '''
    if (verifyAccount) {
        try {
            auto anisette = AnisetteDataManager::instance()->FetchAnisetteData();
            auto handler = []() -> pplx::task<std::optional<std::string>> {
                return pplx::create_task([]() -> std::optional<std::string> {
                    std::cout << "Enter two factor code" << std::endl;
                    std::string code;
                    if (!(std::cin >> code)) return std::nullopt;
                    return code;
                });
            };
            // Use the same Apple authentication implementation as installation.
            // Authenticate obtains the Apple session and fetches the account.
            AppleAPI::getInstance()->Authenticate(appleID, password, anisette, handler).get();
            std::cout << "Account authentication succeeded." << std::endl;
            return 0;
        } catch (Error& error) {
            std::cerr << "Authentication failed: " << error.localizedDescription()
                      << " (" << error.code() << ")." << std::endl;
        } catch (std::exception& error) {
            // Never print arbitrary response data or credentials.
            std::cerr << "Authentication failed: signing service could not complete sign-in." << std::endl;
        }
        return 1;
    }
'''
new = new.replace('\tif (installApp) {', verification + '\n\tif (installApp) {')
assert new != old and '--verify-account' in new
patch = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                  fromfile='a/src/AltServerMain.cpp', tofile='b/src/AltServerMain.cpp'))
Path(__file__).resolve().parents[1].joinpath('altserver/account-verification.patch').write_text(patch, newline='\n')
