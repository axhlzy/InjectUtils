/*
 * This file is part of QBDI.
 *
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef QBDI_VERSION_H_
#define QBDI_VERSION_H_

#include <stdint.h>
#include "QBDI/Platform.h"

#ifdef __cplusplus
namespace QBDI {
extern "C" {
#endif

#define QBDI_VERSION ((0 << 16 ) | \
                      (11 << 8 ) | \
                      (0 << 0 ))
#define QBDI_VERSION_STRING "0.11.0"

#define QBDI_VERSION_MAJOR 0
#define QBDI_VERSION_MINOR 11
#define QBDI_VERSION_PATCH 0
#define QBDI_VERSION_DEV 0

#define QBDI_ARCHITECTURE_STRING "AARCH64"
#define QBDI_PLATFORM_STRING "android"

/*! Return QBDI version.
 *
 * @param[out] version  QBDI version encoded as an unsigned integer (0xMMmmpp).
 * @return  QBDI version as a string (major.minor.patch).
 */
QBDI_EXPORT const char* qbdi_getVersion(uint32_t* version);

#ifdef __cplusplus
/*! Return QBDI version.
 *
 * @param[out] version  QBDI version encoded as an unsigned integer (0xMMmmpp).
 * @return  QBDI version as a string (major.minor.patch).
 */
inline const char* getVersion(uint32_t* version) {
    return qbdi_getVersion(version);
}

} // "C"
} // QBDI::
#endif

#endif // QBDI_VERSION_H_
