cmake_minimum_required(VERSION 3.13.4)
project(scs)

set(CMAKE_CXX_STANDARD 17)

# set your llvm path here
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} "D:/ThirdParty/LLVM")
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

llvm_map_components_to_libnames(llvm_libs support core irreader)
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})

set(header_files
scs/scs.hpp
scs/llvm_scs.hpp
)

set(source_files
scs/main.cpp
)

set(all_files ${header_files} ${source_files})

source_group(TREE ${CMAKE_SOURCE_DIR} FILES ${all_files})
add_executable(scs ${all_files})

target_include_directories(scs PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(scs PUBLIC ${LLVM_DEFINITIONS_LIST})
target_link_libraries(scs ${llvm_libs})