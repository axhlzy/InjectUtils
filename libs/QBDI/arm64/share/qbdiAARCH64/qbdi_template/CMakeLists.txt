cmake_minimum_required (VERSION 3.2)
project(QBDITemplate)

find_package(QBDIAARCH64 REQUIRED)

add_executable(qbdi_template qbdi_template.c)

# Easier to build using QBDI static library on Windows
if(MSVC)
  target_link_libraries(qbdi_template QBDI::AARCH64::QBDI_static)
else()
  target_link_libraries(qbdi_template QBDI::AARCH64::QBDI)
endif()
