cmake_minimum_required(VERSION 3.20)
project(hawkeye_ddos CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_library(XGBOOST_LIB xgboost REQUIRED
    HINTS ${CMAKE_SOURCE_DIR}/xgboost/lib /usr/local/lib /usr/lib)
find_path(XGBOOST_INC xgboost/c_api.h REQUIRED
    HINTS ${CMAKE_SOURCE_DIR}/xgboost/include /usr/local/include /usr/include)

add_executable(predictor src/predictor.cpp)

target_include_directories(predictor PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${XGBOOST_INC}
    kern/
)

target_link_libraries(predictor PRIVATE
    ${LIBBPF_LIBRARIES}
    ${XGBOOST_LIB}
    pthread elf z
)

target_compile_options(predictor PRIVATE
    ${LIBBPF_CFLAGS} -O2 -Wall -Wextra -Werror
    -fstack-protector-strong -D_FORTIFY_SOURCE=2
)
