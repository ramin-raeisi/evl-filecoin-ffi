#---------------------------------------------------------------------------#
# Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_find_package(${CMAKE_WORKSPACE_NAME}_block)
cm_find_package(${CMAKE_WORKSPACE_NAME}_codec)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       filecoin::proofs
                       filecoin::storage_proofs

                       crypto3::algebra
                       crypto3::block
                       crypto3::codec
                       crypto3::hash
                       crypto3::zk

                       ${Boost_LIBRARIES})

macro(define_signer_test name)
    cm_test(NAME signer_${name}_test SOURCES ${name}.cpp)

    target_include_directories(signer_${name}_test PRIVATE
                               $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                               $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(signer_${name}_test PROPERTIES CXX_STANDARD 14)

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(signer_${name}_test PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

set(TESTS_NAMES
    bls_api
    proofs_api)

foreach(TEST_NAME ${TESTS_NAMES})
    define_signer_test(${TEST_NAME})
endforeach()