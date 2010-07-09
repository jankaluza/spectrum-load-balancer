project(spectrum-load-balancer)
 
cmake_minimum_required(VERSION 2.6.0 FATAL_ERROR)
if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)
 
file(WRITE src/transport_config.h "\n")
 
set(CMAKE_MODULE_PATH "cmake_modules")
include_directories(src)
 
 
set(gloox_DIR "${CMAKE_SOURCE_DIR}/cmake_modules")
find_package(gloox REQUIRED)
set(glib_DIR "${CMAKE_SOURCE_DIR}/cmake_modules")
find_package(glib REQUIRED)
 
include_directories(${GLOOX_INCLUDE_DIR})

if(GLIB2_FOUND)
	include_directories(${GLIB2_INCLUDE_DIR})
	message( STATUS "Found GLIB2: ${GLIB2_INCLUDE_DIR} ${GLIB2_LIBRARIES}")
else(GLIB2_FOUND)
	message(FATAL_ERROR "No GLIB2")
endif(GLIB2_FOUND)


if(CMAKE_BUILD_TYPE MATCHES Debug)
	ADD_DEFINITIONS(-ggdb)
	ADD_DEFINITIONS(-DDEBUG)
	ADD_DEFINITIONS(-Wall)
	ADD_DEFINITIONS(-W)
	ADD_DEFINITIONS(-Wcast-align)
	ADD_DEFINITIONS(-Wextra -Wno-sign-compare -Wno-unused-parameter)
#	ADD_DEFINITIONS(-Werror=format-security)
	ADD_DEFINITIONS(-Winit-self)
	ADD_DEFINITIONS(-Wmissing-declarations)
#	ADD_DEFINITIONS(-Wmissing-noreturn)
	ADD_DEFINITIONS(-Wpointer-arith)
	ADD_DEFINITIONS(-Wreorder)
	ADD_DEFINITIONS(-Woverloaded-virtual)
	ADD_DEFINITIONS(-Wsign-promo)
	ADD_DEFINITIONS(-Wundef -Wunused)
#	ADD_DEFINITIONS(-Weffc++)
#	ADD_DEFINITIONS(-pedantic)
	message(STATUS "Build type is set to Debug")
endif(CMAKE_BUILD_TYPE MATCHES Debug)

#CONFIGURE_FILE(config.h.in config.h)

set(spectrum-load-balancer_SRCS
	src/component.cpp
	src/configfile.cpp
	src/log.cpp
# 	src/main.cpp
)

set(spectrum-load-balancer_MOC_HDRS
	src/component.h
	src/configfile.h
	src/log.h
# 	src/main.h
)

add_executable(spectrum-load-balancer ${spectrum-load-balancer_SRCS} ${lrelease_outputs})

if(DEFINED WITH_STATIC_GLOOX)
	target_link_libraries(spectrum-load-balancer ${WITH_STATIC_GLOOX} -lgnutls ${GLIB2_LIBRARIES} -export-dynamic)
else(DEFINED WITH_STATIC_GLOOX)
	target_link_libraries(spectrum-load-balancer ${GLOOX_LIBRARIES} ${GLIB2_LIBRARIES} -export-dynamic)
endif(DEFINED WITH_STATIC_GLOOX)

message(STATUS "Spectrum-load-balancer will be installed into: " ${CMAKE_INSTALL_PREFIX})
file(APPEND src/transport_config.h "#define INSTALL_DIR \"" ${CMAKE_INSTALL_PREFIX} "\"\n")

if (SPECTRUM_VERSION)
	file(APPEND src/transport_config.h "#define VERSION \"" ${SPECTRUM_VERSION} "\"\n")
else (SPECTRUM_VERSION)
	if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
		execute_process(COMMAND git "--git-dir=${CMAKE_CURRENT_SOURCE_DIR}/.git" rev-parse --short HEAD
						OUTPUT_VARIABLE GIT_REVISION
						OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		file(APPEND src/transport_config.h "#define VERSION \"0.1-git-" ${GIT_REVISION} "\"\n")
	else (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
		file(APPEND src/transport_config.h "#define VERSION \"0.1\"\n")
	endif (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
endif (SPECTRUM_VERSION)

INSTALL(TARGETS spectrum-load-balancer
    RUNTIME DESTINATION bin
    )
