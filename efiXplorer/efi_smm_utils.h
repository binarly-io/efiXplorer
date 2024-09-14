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
 */

#pragma once

#include "efi_utils.h"

ea_list_t findSmstSwDispatch(ea_list_t bs_list);
ea_list_t findSmstSmmBase(ea_list_t bs_list);
func_list_t findSmiHandlers(ea_t address, std::string prefix);
func_list_t findSmiHandlersSmmDispatch(EfiGuid guid, std::string prefix);
func_list_t findSmiHandlersSmmDispatchStack(json_list_t stackGuids, std::string prefix);
ea_list_t findSmmGetVariableCalls(segment_list_t dataSegments, json_list_t *allServices);
ea_list_t resolveEfiSmmCpuProtocol(json_list_t stackGuids, json_list_t dataGuids,
                                   json_list_t *allServices);
ea_t markChildSwSmiHandler(ea_t ea);
