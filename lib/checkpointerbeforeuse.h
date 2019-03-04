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
#ifndef checkpointerbeforeuseH
#define checkpointerbeforeuseH
//---------------------------------------------------------------------------
#include <map>
#include <utility>

#include "config.h"
#include "check.h"


/// @addtogroup Checks
/** @brief Various small checks for automatic variables */
/// @{

class CPPCHECKLIB CheckPointerBeforeUse : public Check {
public:
    /** This constructor is used when registering the CheckClass */
    CheckPointerBeforeUse() : Check(myName()) {}

    /** This constructor is used when running checks. */
    CheckPointerBeforeUse(const Tokenizer* tokenizer, const Settings* settings, ErrorLogger* errorLogger)
        : Check(myName(), tokenizer, settings, errorLogger) {
                loadConf(settings->userRuleConfigure);
    }
    
    void runSimplifiedChecks(const Tokenizer* tokenizer, const Settings* settings,
            ErrorLogger* errorLogger) override {
        CheckPointerBeforeUse checkPointerBeforeUse(tokenizer, settings, errorLogger);
        checkPointerBeforeUse.wrongUse();
    }
    
    /* Get the token that dereference, then judge if check the variable before dereference it.*/
    void wrongUse();
    void getErrorMessages(ErrorLogger* errorLogger, const Settings* settings) const override {}

private:
    void loadConf(const YAML::Node &configure);
    void report_error_info(const Token* tok);
    void report_warning_info(const Token* tok);
    bool isSkip(const Token* tok);
    bool isContainerType(const Token* tok);
    bool is_check_filter() {
        return false;
    }

    /**
     * E.g.:
     *     1. a->b->c
     *     2. a->b()->c()->d
     */
    void getContinousPointer(const Scope* scope, 
        std::vector<std::string> &continuous_pointer,
        std::vector<std::string> &continuous_pointer_original,
        std::vector<std::map<int, Token*>> &continuous_pointer_token);
    
    /**
     * Is there a pointer dereference? Everything that should result in
     * a nullpointer dereference error message will result in a true
     * return value. If it's unknown if the pointer is dereferenced false
     * is returned.
     * @param tok token for the pointer
     * @param unknown it is not known if there is a pointer dereference (could be reported as a debug message)
     * @return true => there is a dereference
     */
    bool isPointerDeRef(const Token *tok, bool &unknown);

    bool isCheckNull(const Scope *scope, const Token *tok);
    void checkContinousNull(const Scope *scope, 
        std::vector<std::string> &continuous_pointer,
        std::vector<std::string> &continuous_pointer_original,
        std::vector<std::map<int, Token*>> &continuous_pointer_token);
    /**
     * review the check result strategy. 
     * This function contains the result filter strategy for the product:
     * 1. If the pointer's null-check operation done in other function.
     * 2. If the product has its owner check-null macro, e.g. checknull().
     * 
     * @return false=> after review, this token not check-null, must monitor.
     */
    bool resultReview();
    std::string getTokenString(const Token* begin, const Token* end) const;
    std::string classInfo() const override {
        return "test";
    }
    static std::string myName() {
        return "CheckPointerBeforeUse";
    }

private:
    std::vector<std::string> mFilterContainerType;
};
/// @}
//---------------------------------------------------------------------------
#endif //checkpointerbeforeuseH
