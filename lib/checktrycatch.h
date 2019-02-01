/*
 * Cppcheck - A tool for static C/C++ code analysis
 * Copyright (C) 2007-2016 Cppcheck team.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


//---------------------------------------------------------------------------
#ifndef checktrycatchfuncH
#define checktrycatchfuncH
//---------------------------------------------------------------------------

#include "config.h"
#include "check.h"
#include <vector>
#include <set>
#include <algorithm>
#include <iostream>
#include <string>

/// @addtogroup Checks
/** @brief Various small checks for automatic variables */
/// @{

class CPPCHECKLIB CheckTryCatchFunc : public Check {
public:
    /** This constructor is used when registering the CheckClass */
    CheckTryCatchFunc() : Check(myName()) {}

    /** This constructor is used when running checks. */
    CheckTryCatchFunc(const Tokenizer* tokenizer, const Settings* settings, ErrorLogger* errorLogger)
        : Check(myName(), tokenizer, settings, errorLogger) {
                loadConf(settings->userRuleConfigure);
                beginpattern = "try";
                endpattern = "catch";
                allexceptiontypepattern = ". . .";
    }
    
    void runSimplifiedChecks(const Tokenizer* tokenizer, const Settings* settings,
            ErrorLogger* errorLogger) override {
        CheckTryCatchFunc checkTryCatchFunc(tokenizer, settings, errorLogger);
        checkTryCatchFunc.wrongUse();
    }
 
    void wrongUse();
    void getErrorMessages(ErrorLogger* errorLogger, const Settings* settings) const override {}

private:
    void loadConf(const YAML::Node &configure);
    bool is_target(const Token *tok, std::set<std::string>& exception_patterns);
    void report_error_info(const Token* tok);
    void report_warning_info(const Token* tok);
    void report_error_exception_info(const Token* tok);
    bool check_catches_exception_type(const Token* startCatchToken);
    bool check_single_catch_exception_type(const Token* catchToken);
    
    bool is_check_filter() {
        if (_except_info.empty()) {
            std::cout << "can not find configure for CheckTryCatchFunc, this check will be filter" << std::endl;
            return true;
        }
        return false;
    }

    std::string classInfo() const override {
        return "function may throw exception.\n"
               "Who use it have to catch exception.\n";
    }
    static std::string myName() {
        return "CheckTryCatchFunc";
    }
    

    struct sExceptInfo {
        std::string class_name;
        std::set<std::string> func_names;
        std::set<std::string> exception_patterns;
    };

    struct sExceptComp {
        bool operator () (const sExceptInfo& left, const sExceptInfo& right) const {
            if (left.class_name <  right.class_name) {
                return true;
            }
            else {
                if (left.func_names.size() < right.func_names.size()) {
                    return true;
                }
                auto it_left = left.func_names.begin();
                auto it_right = right.func_names.begin();
                for (; it_left != left.func_names.end(); ++it_left, ++it_right) {
                    if (*it_left < *it_right) {
                        return true;
                    }
                }
            }
            return false;
        }
    };

    std::string beginpattern;
    std::string endpattern;
    std::string allexceptiontypepattern;
    std::set<std::string> exceptiontypepattern;
    static std::set<sExceptInfo, sExceptComp> _except_info;
};
/// @}
//---------------------------------------------------------------------------
#endif //checktrycatchfuncH
