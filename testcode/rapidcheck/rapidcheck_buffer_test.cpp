/**
 * @file rapidcheck_buffer_test.cpp
 * @brief RapidCheck property-based tests for BSL buffer operations
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "bsl_buffer.h"
#include "bsl_errno.h"

using namespace rc;

int main() {
    /**
     * @test BSL_BufMem grow and read
     * @property Buffer can grow and hold data
     * @generalizes SDV_BSL_BUFFER_API_TC001 - Buffer operations
     * @see testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
     */
    rc::check("BSL_BufMem can grow and hold data",
        [](const std::vector<uint8_t> &data) {
            RC_PRE(data.size() > 0);
            RC_PRE(data.size() <= 1024);
            
            BSL_BufMem *buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            size_t growRet = BSL_BufMemGrowClean(buf, data.size());
            RC_ASSERT(growRet >= data.size());
            
            std::memcpy(buf->data, data.data(), data.size());
            buf->length = data.size();
            
            RC_ASSERT(buf->length == data.size());
            RC_ASSERT(std::memcmp(buf->data, data.data(), data.size()) == 0);
            
            BSL_BufMemFree(buf);
        });

    /**
     * @test BSL_BufMem initial state
     * @property New buffer has zero length
     * @generalizes SDV_BSL_BUFFER_API_TC002 - Initial state test
     * @see testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
     */
    rc::check("BSL_BufMem initial state is empty",
        []() {
            BSL_BufMem *buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            RC_ASSERT(buf->length == 0);
            
            BSL_BufMemFree(buf);
        });

    /**
     * @test BSL_BufMem grow increases capacity
     * @property Growing buffer increases max capacity
     * @generalizes SDV_BSL_BUFFER_API_TC003 - Grow test
     * @see testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
     */
    rc::check("BSL_BufMem grow increases capacity",
        [](size_t size) {
            RC_PRE(size > 0);
            RC_PRE(size <= 4096);
            
            BSL_BufMem *buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            size_t initialMax = buf->max;
            
            size_t newMax = BSL_BufMemGrowClean(buf, size);
            RC_ASSERT(newMax >= size);
            RC_ASSERT(buf->max >= size);
            
            BSL_BufMemFree(buf);
        });

    /**
     * @test BSL_BufMem multiple grows
     * @property Multiple grows work correctly
     * @generalizes SDV_BSL_BUFFER_API_TC004 - Multiple grow test
     * @see testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
     */
    rc::check("BSL_BufMem multiple grows work",
        [](size_t size1, size_t size2) {
            RC_PRE(size1 > 0);
            RC_PRE(size2 > 0);
            RC_PRE(size1 + size2 <= 4096);
            
            BSL_BufMem *buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            BSL_BufMemGrowClean(buf, size1);
            size_t max1 = buf->max;
            
            BSL_BufMemGrowClean(buf, size1 + size2);
            RC_ASSERT(buf->max >= size1 + size2);
            
            BSL_BufMemFree(buf);
        });

    /**
     * @test BSL_BufMem free and reallocate
     * @property Free and reallocate works
     * @generalizes SDV_BSL_BUFFER_API_TC005 - Free/reallocate test
     * @see testcode/sdv/testcase/bsl/buffer/test_suite_sdv_buffer.c
     */
    rc::check("BSL_BufMem free and reallocate",
        [](const std::vector<uint8_t> &data1, const std::vector<uint8_t> &data2) {
            RC_PRE(data1.size() > 0);
            RC_PRE(data2.size() > 0);
            RC_PRE(data1.size() <= 512);
            RC_PRE(data2.size() <= 512);
            
            BSL_BufMem *buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            BSL_BufMemGrowClean(buf, data1.size());
            std::memcpy(buf->data, data1.data(), data1.size());
            buf->length = data1.size();
            
            BSL_BufMemFree(buf);
            
            buf = BSL_BufMemNew();
            RC_PRE(buf != nullptr);
            
            BSL_BufMemGrowClean(buf, data2.size());
            std::memcpy(buf->data, data2.data(), data2.size());
            buf->length = data2.size();
            
            RC_ASSERT(std::memcmp(buf->data, data2.data(), data2.size()) == 0);
            
            BSL_BufMemFree(buf);
        });

    return 0;
}