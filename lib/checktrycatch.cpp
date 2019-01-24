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
// Auto variables checks
//---------------------------------------------------------------------------

#include "checktrycatch.h"
#include "symboldatabase.h"

#include <string>
#include <iostream>
#include <algorithm>

//---------------------------------------------------------------------------


// Register this check class into cppcheck by creating a static instance of it..
namespace {
static CheckTryCatchFunc instance;
}

static const CWE CWE398(398U);  // Indicator of Poor Code Quality
static const CWE CWE562(562U);  // Return of Stack Variable Address
static const CWE CWE590(590U);  // Free of Memory not on the Heap

std::set<CheckTryCatchFunc::sExceptInfo, CheckTryCatchFunc::sExceptComp> CheckTryCatchFunc::_except_info;

// 需要根据具体的业务代码需求来设计
bool CheckTryCatchFunc::is_target(const Token *tok, std::set<std::string>& exception_patterns) {
    for (auto& ex : _except_info) {
        for (auto& func : ex.func_names) {
            if (Token::Match(tok, (func + " (").c_str()) && tok->linkAt(1)) {
                if (ex.class_name.empty()) {//any type
                    if (tok->strAt(-1) == "." && tok->tokAt(-1) && !(tok->tokAt(-1)->isLiteral())) {
                        exception_patterns = ex.exception_patterns;
                        return true;
                    }
                }
                else if (ex.class_name == "::") {//gloable function
                    if (tok->strAt(-1) != ".") {
                        exception_patterns = ex.exception_patterns;
                        return true;
                    }
                }
                else {
                    const Token* var_tok = tok->astParent()->astOperand1();

                    if (!var_tok || !var_tok->variable()) {
                        return false;
                    }

                    const std::string type_str = var_tok->str();

                    if (type_str.find(ex.class_name) != std::string::npos) {
                         exception_patterns = ex.exception_patterns;
                         return  true;
                    }
                }
            }
        }
    }

    return false;
}

void CheckTryCatchFunc::wrongUse() {
    const SymbolDatabase* symbolDatabase = mTokenizer->getSymbolDatabase();
    for (const Scope* scope : symbolDatabase->functionScopes) {
        const Token* endToken = scope->bodyEnd;
        for (const Token* tok = scope->bodyStart; tok && tok != endToken; tok = tok->next()) {
            if (is_target(tok, exceptiontypepattern)) { // 如果是配置中指定的函数
                
                // 在当前函数scope中该tok之前寻找是否存在try，
                // 该策略适用于没有try嵌套的代码，如果存在try嵌套try { try{} catch() {} %%tok;} catch() {}
                // 则会存在误报的情况。
                const Token* tempTok = tok;
                while (tempTok != scope->bodyStart && 
                        !Token::Match(tempTok, beginpattern.c_str())) {
                    tempTok = tempTok->previous(); 
                }

                // 如果不存在try，则说明异常，同时停止该函数的检查，并检查下一个函数。
                if (tempTok == scope->bodyStart) {
                    report_error_info(tok);
                    break;
                }

                // 如果存在try，需要判断待检查的token是否位于try代码块中。
                const Token* tryToken = tempTok;

                // now, from "try" to find first "catch"
                const Token* catchToken = tryToken->next()->link()->next();

                bool isTry = false;
                for (const Token* testToken = tryToken; testToken && testToken != catchToken; 
                     testToken = testToken->next()) {
                    if (Token::Match(testToken, tok->strAt(0).c_str())) {
                        isTry = true;
                        break;
                    }
                }
                if (!isTry) {
                    report_error_info(tok);
                }

                // check if catch(es) have righe exceptType
                if (!check_catches_exception_type(catchToken)) {
                    report_error_exception_info(tok);
                    break;
                }
            }
        }
    }    
}

bool CheckTryCatchFunc::check_catches_exception_type(const Token* startCatchToken) {
    const Token* nextCatchToken = startCatchToken;
    while (nextCatchToken) {
        // check if catchToken str is all uppper char
        std::string temp_str = nextCatchToken->str();
        std::transform(temp_str.begin(), temp_str.end(), temp_str.begin(), ::toupper);
        if (temp_str == nextCatchToken->str() && temp_str.size() > 1) {
            return true;
        }

        if (!Token::Match(nextCatchToken, endpattern.c_str())) {
            break;        
        }

        // check if catchToken match right exceptType
        if (check_single_catch_exception_type(nextCatchToken)) {
            return true;
        }

        nextCatchToken = nextCatchToken->next()->link()->next()->link()->next(); 
    }

    // no catch match right exceptType
    return false;
}

bool CheckTryCatchFunc::check_single_catch_exception_type(const Token* catchToken) {
    if (!catchToken->next()->link()) {
        return false;
    }

    const Token* exceptionToken = catchToken->next()->link()->previous();
    if (!exceptionToken->variable()) {
        if (Token::Match(catchToken->next()->next(), allexceptiontypepattern.c_str())) {
            return true;
        }
        return false;
    }

    if (!(exceptionToken->variable()->isReference() || exceptionToken->variable()->isPointer())) {
        report_warning_info(catchToken);
    }

    std::string exceptionVarTypeStr = "";
    for (const Token* typeToken = exceptionToken->variable()->typeStartToken(); 
         typeToken && typeToken != exceptionToken->variable()->typeEndToken()->next();
         typeToken = typeToken->next()
         ) {
        exceptionVarTypeStr += (typeToken->str() + " ");
    }
    
    for (auto& exceptiontype_item : exceptiontypepattern) {
        if (exceptionVarTypeStr.find(exceptiontype_item.c_str()) != std::string::npos) {
            return true;
        }
    }

    return false;
}

void CheckTryCatchFunc::_load_conf() {
    sExceptInfo info;
    info.class_name = std::string("::");
    info.func_names.insert(std::string("lexical_cast < %name% >"));
    info.exception_patterns.insert(std::string("boost :: bad_lexical_cast"));
    info.exception_patterns.insert(std::string("my :: bad_lexical_cast"));
    _except_info.insert(info);
}

void CheckTryCatchFunc::report_error_info(const Token* tok) {
    reportError(
            tok,
            Severity::error,
            "trycatchmiss",
            tok->str() + " may throw exception, need try and catch",
            CWE562,
            false
    );
}

void CheckTryCatchFunc::report_error_exception_info(const Token* tok) {
    reportError(
            tok,
            Severity::error,
            "exceptiontypewrong",
            tok->str() + " the exception type in the catch is wrong",
            CWE562,
            false
    );
}


void CheckTryCatchFunc::report_warning_info(const Token* tok) {
    reportError(
            tok,
            Severity::warning,
            "exception type error",
            "exception variable must be Pointer or Reference",
            CWE562,
            false
    );
}