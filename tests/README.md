# AES Tests

This project now separates test code from the root `main.cpp`.

## Structure

- `tests/unit/unit_tests.cpp`: deterministic known-answer unit vectors.
- `tests/system/system_tests.cpp`: API and integration-style behavior checks.

## Build and run (PowerShell)

From the `AES_Encryption` folder:

```powershell
C:\msys64\ucrt64\bin\g++.exe -std=c++17 -g AES128_Encrypt.cpp tests\unit\unit_tests.cpp -o unit_tests.exe
.\unit_tests.exe

C:\msys64\ucrt64\bin\g++.exe -std=c++17 -g AES128_Encrypt.cpp tests\system\system_tests.cpp -o system_tests.exe
.\system_tests.exe
```

Exit code `0` means all tests in that suite passed.
