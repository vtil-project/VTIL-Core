This documentation explains how to build VTIL on Windows with Visual Studio.

1. Dependency

  - See [COMPILE.md](COMPILE.md)
  - Open Command, from the root directory of the source, do:
  
        $ mklink /J Capstone build\_deps\capstone-src
        $ mklink /J Keystone build\_deps\keystone-src
        
    Or you can git clone capstone and keystone by yourself to these two directories.
    

2. Enter `Capstone\msvc\capstone_static`, use Visual Studio to build `capstone_static.vcxproj` (Debug/Release with x86/x64)


3. Enter Keystone, Open the Command Prompt, and from the root directory of Keystone source, follow these steps:

        $ mkdir build
        $ cd build

        $ mkdir llvm && mkdir llvm\lib
        $ mkdir llvm\lib\Release && mkdir llvm\lib\Debug
        $ mkdir llvm\lib\x64 && mkdir llvm\lib\x64\Release && mkdir llvm\lib\x64\Debug

        $ call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" # replace with your visual studio path
        $ del /Q CMakeCache.txt
        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -DLLVM_USE_CRT_RELEASE=MD -DKEYSTONE_BUILD_STATIC_RUNTIME=0 -DBUILD_LIBS_ONLY=1 -G "NMake Makefiles" .. 
        $ nmake && copy /Y llvm\lib\keystone.lib llvm\lib\Release\

        $ call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
        $ del /Q CMakeCache.txt
        $ cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -DLLVM_USE_CRT_DEBUG=MDd -DKEYSTONE_BUILD_STATIC_RUNTIME=0 -DBUILD_LIBS_ONLY=1 -G "NMake Makefiles" ..
        $ nmake && copy /Y llvm\lib\keystone.lib llvm\lib\Debug\

        $ call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" # replace with your visual studio path
        $ del /Q CMakeCache.txt
        $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -DLLVM_USE_CRT_RELEASE=MD -DKEYSTONE_BUILD_STATIC_RUNTIME=0 -DBUILD_LIBS_ONLY=1 -G "NMake Makefiles" ..
        $ nmake && copy /Y llvm\lib\keystone.lib llvm\lib\x64\Release\

        $ call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
        $ del /Q CMakeCache.txt
        $ cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="all" -DLLVM_USE_CRT_DEBUG=MDd -DKEYSTONE_BUILD_STATIC_RUNTIME=0 -DBUILD_LIBS_ONLY=1 -G "NMake Makefiles" ..
        $ nmake && copy /Y llvm\lib\keystone.lib llvm\lib\x64\Debug\


4. Open `VTIL-Core.sln`, Now you can build VTIL in VS.

