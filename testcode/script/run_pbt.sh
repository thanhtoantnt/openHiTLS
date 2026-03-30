#!/bin/bash

# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HITLS_ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RAPIDCHECK_DIR="${HITLS_ROOT_DIR}/testcode/rapidcheck"
RAPIDCHECK_BUILD_DIR="${RAPIDCHECK_DIR}/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

print_banner() {
    echo -e "${BLUE}"
    echo "======================================================================"
    echo "           Property-Based Testing with RapidCheck"
    echo "======================================================================"
    echo -e "${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_NAMES...]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -b, --build         Build PBT tests before running"
    echo "  -c, --clean         Clean build directory before building"
    echo "  -j, --jobs N        Number of parallel jobs for building (default: auto)"
    echo "  -v, --verbose       Show verbose output"
    echo "  -l, --list          List available tests"
    echo "  --seed SEED         Set random seed for test generation"
    echo "  --num-tests N       Number of test cases per property (default: 100)"
    echo ""
    echo "Test Names:"
    echo "  aes                 Run AES property tests"
    echo "  hash                Run SM3 hash property tests"
    echo "  sha2                Run SHA-2 property tests"
    echo "  sm4                 Run SM4 property tests"
    echo "  bn                  Run Big Number property tests"
    echo "  base64              Run Base64 property tests"
    echo "  opt                 Run App Option property tests"
    echo "  md5                 Run MD5 hash property tests"
    echo "  sha1                Run SHA-1 hash property tests"
    echo "  chacha20            Run ChaCha20 stream cipher property tests"
    echo "  buffer              Run Buffer operations property tests"
    echo "  all                 Run all tests (default)"
    echo ""
    echo "Examples:"
    echo "  $0                  # Run all PBT tests"
    echo "  $0 -b               # Build and run all tests"
    echo "  $0 aes sm4          # Run only AES and SM4 tests"
    echo "  $0 --seed 12345     # Run with specific seed"
    echo ""
}

list_tests() {
    echo "Available PBT tests:"
    echo "  aes       - AES encryption/decryption properties"
    echo "  hash      - SM3 hash function properties"
    echo "  sha2      - SHA-224/256/384/512 hash properties"
    echo "  sm4       - SM4 block cipher properties"
    echo "  bn        - Big Number arithmetic properties"
    echo "  base64    - Base64 encoding/decoding properties"
    echo "  opt       - Application option parsing properties"
    echo "  md5       - MD5 hash function properties"
    echo "  sha1      - SHA-1 hash function properties"
    echo "  chacha20  - ChaCha20 stream cipher properties"
    echo "  buffer    - Buffer operations properties"
}

check_prerequisites() {
    echo -e "${BLUE}[INFO] Checking prerequisites...${NC}"
    
    if [ ! -d "${HITLS_ROOT_DIR}/build" ]; then
        echo -e "${RED}[ERROR] openHiTLS not built. Run 'python3 configure.py && cmake .. && make' first.${NC}"
        exit 1
    fi
    
    if [ ! -f "${HITLS_ROOT_DIR}/build/libhitls_crypto.a" ]; then
        echo -e "${RED}[ERROR] libhitls_crypto.a not found. Build openHiTLS first.${NC}"
        exit 1
    fi
    
    if [ ! -f "${HITLS_ROOT_DIR}/platform/Secure_C/lib/libboundscheck.a" ]; then
        echo -e "${RED}[ERROR] libboundscheck.a not found. Initialize git submodules.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[OK] All prerequisites satisfied.${NC}"
}

build_tests() {
    echo -e "${BLUE}[INFO] Building PBT tests...${NC}"
    
    local CLEAN_BUILD=0
    local JOBS=""
    
    if [ "$CLEAN" -eq 1 ]; then
        CLEAN_BUILD=1
    fi
    
    if [ -n "$NUM_JOBS" ]; then
        JOBS="-j${NUM_JOBS}"
    else
        if [[ "$(uname)" == "Darwin" ]]; then
            JOBS="-j$(sysctl -n hw.ncpu)"
        else
            JOBS="-j$(grep -c ^processor /proc/cpuinfo)"
        fi
    fi
    
    mkdir -p "${RAPIDCHECK_BUILD_DIR}"
    cd "${RAPIDCHECK_BUILD_DIR}"
    
    if [ "$CLEAN_BUILD" -eq 1 ]; then
        echo -e "${YELLOW}[INFO] Cleaning build directory...${NC}"
        rm -rf "${RAPIDCHECK_BUILD_DIR}"/*
    fi
    
    echo -e "${BLUE}[INFO] Running CMake...${NC}"
    cmake .. 2>&1 | while read -r line; do
        if [ "$VERBOSE" -eq 1 ]; then
            echo "$line"
        fi
    done
    
    echo -e "${BLUE}[INFO] Building with ${JOBS}...${NC}"
    make ${JOBS} 2>&1 | while read -r line; do
        if [ "$VERBOSE" -eq 1 ]; then
            echo "$line"
        elif echo "$line" | grep -q "error:"; then
            echo -e "${RED}$line${NC}"
        fi
    done
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Build failed.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[OK] Build successful.${NC}"
    cd "${SCRIPT_DIR}"
}

run_single_test() {
    local TEST_NAME=$1
    local TEST_EXEC="${RAPIDCHECK_BUILD_DIR}/rapidcheck_${TEST_NAME}_test"
    
    if [ ! -f "$TEST_EXEC" ]; then
        echo -e "${YELLOW}[SKIP] Test executable not found: ${TEST_EXEC}${NC}"
        ((SKIPPED_TESTS++))
        return 0
    fi
    
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}Running: ${TEST_NAME}${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    
    local CMD="$TEST_EXEC"
    
    if [ -n "$SEED" ]; then
        export RC_SEED="$SEED"
    fi
    
    if [ -n "$NUM_TESTS" ]; then
        export RC_PARAMS="maxSuccess=${NUM_TESTS}"
    fi
    
    local START_TIME=$(date +%s)
    
    if [ "$VERBOSE" -eq 1 ]; then
        $CMD 2>&1
        local EXIT_CODE=$?
    else
        $CMD 2>&1 | while IFS= read -r line; do
            if echo "$line" | grep -qE "(OK|Falsifiable|Gave up|Using configuration)"; then
                echo "$line"
            elif echo "$line" | grep -qE "^(std::|RC_)"; then
                echo "$line"
            elif [ "$VERBOSE" -eq 1 ]; then
                echo "$line"
            fi
        done
        local EXIT_CODE=${PIPESTATUS[0]}
    fi
    
    local END_TIME=$(date +%s)
    local DURATION=$((END_TIME - START_TIME))
    
    ((TOTAL_TESTS++))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}[PASS] ${TEST_NAME} (${DURATION}s)${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}[FAIL] ${TEST_NAME} (${DURATION}s)${NC}"
        ((FAILED_TESTS++))
    fi
    
    echo ""
}

run_tests() {
    local TESTS_TO_RUN=("$@")
    
    if [ ${#TESTS_TO_RUN[@]} -eq 0 ]; then
        TESTS_TO_RUN=("aes" "hash" "sha2" "sm4" "bn" "base64" "opt" "md5" "sha1" "chacha20" "buffer")
    fi
    
    print_banner
    
    for test in "${TESTS_TO_RUN[@]}"; do
        case "$test" in
            aes|hash|sha2|sm4|bn|base64|opt|md5|sha1|chacha20|buffer)
                run_single_test "$test"
                ;;
            all)
                run_tests aes hash sha2 sm4 bn base64 opt md5 sha1 chacha20 buffer
                ;;
            *)
                echo -e "${YELLOW}[WARN] Unknown test: $test${NC}"
                ;;
        esac
    done
}

print_summary() {
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}                           Summary${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo ""
    echo -e "  Total:   ${TOTAL_TESTS}"
    echo -e "  ${GREEN}Passed:  ${PASSED_TESTS}${NC}"
    echo -e "  ${RED}Failed:  ${FAILED_TESTS}${NC}"
    echo -e "  ${YELLOW}Skipped: ${SKIPPED_TESTS}${NC}"
    echo ""
    
    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}[FAILED] Some tests failed.${NC}"
        exit 1
    else
        echo -e "${GREEN}[SUCCESS] All tests passed.${NC}"
        exit 0
    fi
}

BUILD=0
CLEAN=0
VERBOSE=0
LIST=0
SEED=""
NUM_TESTS=""
NUM_JOBS=""
TESTS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -b|--build)
            BUILD=1
            shift
            ;;
        -c|--clean)
            CLEAN=1
            shift
            ;;
        -j|--jobs)
            NUM_JOBS="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -l|--list)
            LIST=1
            shift
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        --num-tests)
            NUM_TESTS="$2"
            shift 2
            ;;
        -*)
            echo -e "${RED}[ERROR] Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
        *)
            TESTS+=("$1")
            shift
            ;;
    esac
done

if [ $LIST -eq 1 ]; then
    list_tests
    exit 0
fi

check_prerequisites

if [ $BUILD -eq 1 ] || [ ! -f "${RAPIDCHECK_BUILD_DIR}/rapidcheck_aes_test" ]; then
    build_tests
fi

run_tests "${TESTS[@]}"
print_summary