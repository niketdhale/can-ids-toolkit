cmake_minimum_required(VERSION 3.16)
project(can-ids-toolkit LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(can_ids_core STATIC src/CanIdsEngine.cpp)
target_include_directories(can_ids_core PUBLIC include)

add_executable(can_ids_cli apps/can_ids_cli/main.cpp)
target_link_libraries(can_ids_cli PRIVATE can_ids_core)

install(TARGETS can_ids_core can_ids_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)