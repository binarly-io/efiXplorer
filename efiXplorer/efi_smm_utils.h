/*
 * efiXplorer
 * Copyright (C) 2020-2024 Binarly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * efiSmmUtils.h
 *
 */

#pragma once

#include "efi_utils.h"

std::vector<ea_t> findSmstSwDispatch(std::vector<ea_t> gBsList);
std::vector<ea_t> findSmstSmmBase(std::vector<ea_t> gBsList);
std::vector<func_t *> findSmiHandlers(ea_t address, std::string prefix);
std::vector<func_t *> findSmiHandlersSmmDispatch(EfiGuid guid, std::string prefix);
std::vector<func_t *> findSmiHandlersSmmDispatchStack(std::vector<json> stackGuids,
                                                      std::string prefix);
std::vector<ea_t> findSmmGetVariableCalls(std::vector<segment_t *> dataSegments,
                                          std::vector<json> *allServices);
std::vector<ea_t> resolveEfiSmmCpuProtocol(std::vector<json> stackGuids,
                                           std::vector<json> dataGuids,
                                           std::vector<json> *allServices);
ea_t markChildSwSmiHandler(ea_t ea);
