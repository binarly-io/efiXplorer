/*
 * efiXplorer
 * Copyright (C) 2020-2022 Binarly
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

#include "efiUtils.h"

struct EfiGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
    std::vector<uchar> uchar_data() {
        std::vector<uchar> res;
        res.push_back(data1 & 0xff);
        res.push_back(data1 >> 8 & 0xff);
        res.push_back(data1 >> 16 & 0xff);
        res.push_back(data1 >> 24 & 0xff);
        res.push_back(data2 & 0xff);
        res.push_back(data2 >> 8 & 0xff);
        res.push_back(data3 & 0xff);
        res.push_back(data3 >> 8 & 0xff);
        for (auto i = 0; i < 8; i++) {
            res.push_back(data4[i]);
        }
        return res;
    }
};

std::vector<ea_t> findSmstSwDispatch(std::vector<ea_t> gBsList);
std::vector<ea_t> findSmstSmmBase(std::vector<ea_t> gBsList);
std::vector<func_t *> findSmiHandlers(ea_t address);
std::vector<func_t *> findSmiHandlersSmmSwDispatch(std::vector<segment_t *> dataSegments,
                                                   std::vector<json> stackGuids);
std::vector<func_t *> findSmiHandlersSmmSwDispatchStack(std::vector<json> stackGuids);
std::vector<ea_t> findSmmGetVariableCalls(std::vector<segment_t *> dataSegments,
                                          std::vector<json> *allServices);
std::vector<ea_t> resolveEfiSmmCpuProtocol(std::vector<json> stackGuids,
                                           std::vector<json> dataGuids,
                                           std::vector<json> *allServices);
ea_t markSmiHandler(ea_t ea);
