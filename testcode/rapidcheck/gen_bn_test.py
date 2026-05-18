#!/usr/bin/env python3
"""Generate rapidcheck_bn_test.cpp"""

code = r'''#include <rapidcheck.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "crypt_bn.h"

using namespace rc;

...

<｜｜DSML｜｜parameter name="mode" string="true">overwrite