cmake_minimum_required(VERSION 3.1)

cmake_policy(SET CMP0076 NEW)

set(default_build_type "MinSizeRel")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
		STRING "Choose the type of build." FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

project(rrdub)

set(${PROJECT_NAME}_OBJECTS
	rrdub
)

set(${PROJECT_NAME}_LIBRARIES
	rrd
	ubus
	ubox
	blobmsg_json
)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_OBJECTS})
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

find_library(argp_LIBRARY argp)
if (argp_LIBRARY)
	target_link_libraries(${PROJECT_NAME} ${argp_LIBRARY})
endif()

foreach(library ${${PROJECT_NAME}_LIBRARIES})
	find_library(${library}_LIBRARY ${library})
	if (${library}_LIBRARY)
		target_link_libraries(${PROJECT_NAME} ${${library}_LIBRARY})
	else()
		message(FATAL_ERROR "Missing: " ${library})
	endif()
endforeach(library)
