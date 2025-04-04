#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Zydis/Zydis.h>
#include <unordered_map>

#include "../memory/driver.hpp"
#include "../memory/zydis.hpp"

#include "../cheat/structures.h"
#include "../cheat/offsets.hpp"
#include "../cheat/decryption.hpp"

#define TEST_BITD(value, bit) (((value) & (1 << (bit))) != 0)