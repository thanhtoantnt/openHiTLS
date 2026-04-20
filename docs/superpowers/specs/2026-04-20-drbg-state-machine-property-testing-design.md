# DRBG State Machine Property-Based Testing Design

## Overview

Implement property-based testing for the DRBG (Deterministic Random Bit Generator) state machine using a reference model approach. The tests will verify that the implementation's observable behavior matches the expected behavior defined by a simple reference model.

## Background

The DRBG component in openHiTLS implements NIST SP 800-90A compliant random number generation with a well-defined state machine:

- **States**: UNINITIALISED, READY, ERROR
- **Operations**: Instantiate, Generate, Reseed, Uninstantiate
- **Invariants**: Reseed counter behavior, state transition validity

## Architecture

### Reference Model

A simple state machine that tracks:
- Current state (UNINITIALISED, READY, ERROR)
- Reseed counter
- Reseed interval
- Operation history

```
┌──────────────────┐
│  UNINITIALISED   │
└──────────────────┘
        │ Instantiate (success)
        ▼
┌──────────────────┐
│     READY        │◄─────────────┐
└──────────────────┘              │
  │                               │
  │ Generate (success)            │ Reseed
  │ (counter++)                   │ (counter=1)
  ▼                               │
  stays READY                     │
  │                               │
  │ Uninstantiate                 │
  ▼                               │
┌──────────────────┐              │
│  UNINITIALISED   │──────────────┘
└──────────────────┘
        │
        │ Any operation failure
        ▼
┌──────────────────┐
│     ERROR        │
└──────────────────┘
        │ Uninstantiate
        ▼
┌──────────────────┐
│  UNINITIALISED   │
└──────────────────┘
```

### Test Components

1. **Reference Model Implementation**
   - Simple struct tracking state and counters
   - Functions to apply operations and predict outcomes

2. **Property Test Helpers**
   - Random operation sequence generator
   - Deterministic entropy source for reproducibility
   - State comparison functions

3. **Invariant Checkers**
   - State consistency between reference and implementation
   - Reseed counter correctness
   - Error handling correctness

## Properties to Test

### 1. State Transition Validity

| Operation | Valid From States | Result State |
|-----------|-------------------|--------------|
| Instantiate | UNINITIALISED | READY (success) or ERROR (failure) |
| Generate | READY | READY (success) or ERROR (failure) |
| Reseed | READY | READY (success) or ERROR (failure) |
| Uninstantiate | ANY | UNINITIALISED |

### 2. Reseed Counter Invariants

- Counter starts at 1 after successful instantiate
- Counter increments by 1 after each successful generate
- Counter resets to 1 after successful reseed
- Reseed is triggered when counter exceeds reseed interval

### 3. Error Recovery

- Operations in ERROR state return appropriate error codes
- Uninstantiate from ERROR state returns to UNINITIALISED
- After uninstantiate, instantiate can succeed again

### 4. Operation Sequence Properties

- Any valid sequence of operations maintains state consistency
- Generate only succeeds when state is READY
- Fork detection triggers reseed (forkId changes)

## Implementation Details

### File Location

`testcode/sdv/testcase/crypto/drbg/test_suite_sdv_drbg_statemachine.c`

### Test Framework Integration

- Follow existing test patterns from `test_suite_sdv_drbg.c`
- Use existing test macros (ASSERT_EQ, ASSERT_TRUE)
- Use existing entropy/nonce callback infrastructure

### Random Operation Generation

Simple inline generator that produces:
- Random operation type (Instantiate, Generate, Reseed, Uninstantiate)
- Random parameters (output size, adin data)
- Deterministic seed for reproducibility

### Test Cases

1. `SDV_DRBG_STATE_MACHINE_TRANSITION_TC001` - Basic state transitions
2. `SDV_DRBG_STATE_MACHINE_RESEED_COUNTER_TC001` - Counter invariants
3. `SDV_DRBG_STATE_MACHINE_SEQUENCE_TC001` - Random operation sequences
4. `SDV_DRBG_STATE_MACHINE_ERROR_RECOVERY_TC001` - Error state handling
5. `SDV_DRBG_STATE_MACHINE_FORK_TC001` - Fork detection behavior

## Success Criteria

- All state transitions match reference model predictions
- Reseed counter behavior is correct across all operation sequences
- Error recovery works correctly
- No deadlocks or invalid states reached
- Tests are reproducible with deterministic seeds