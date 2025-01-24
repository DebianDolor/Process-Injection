#include "utils.h"
#include "process_injection_remote.h"
#include "process_injection_api_obfuscation.h"
#include "addr_of_entry_point_injection.h"
#include "early_bird_injection.h"
#include "rwx_hunting_injection.h"
#include "process_ghosting.h"
#include <iostream>

int main()
{
    //processInjectionRemote();
    //
    //processInjectionAPIObfuscation();
    //
    //addrOfEntrypointInjection();
    //
    //EarlyBirdInjection();
    //
    //RWXHuntingInjection();
    //
    processGhosting();

    return 0;
}