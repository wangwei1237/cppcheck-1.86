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
#include <iostream>
#include <string>
#include <set>
#include <map>

#include "symboldatabase.h"
#include "checkpointerbeforeuse.h"
//---------------------------------------------------------------------------


// Register this check class into cppcheck by creating a static instance of it..
namespace {
    static CheckPointerBeforeUse instance;
}

namespace {
    const std::set<std::string> stl_stream = {
        "fstream", "ifstream", "iostream", "istream",
        "istringstream", "ofstream", "ostream", "ostringstream",
        "stringstream", "wistringstream", "wostringstream", "wstringstream"
    };
}

static const CWE CWE398(398U);  // Indicator of Poor Code Quality

void CheckPointerBeforeUse::wrongUse() {
    if (is_check_filter()) {
        return;
    }

    const SymbolDatabase* symbolDatabase = mTokenizer->getSymbolDatabase();
    for (const Scope* scope : symbolDatabase->functionScopes) {
        const Token* endToken = scope->bodyEnd;
        std::vector<std::string> vecContinousPointer;
        std::vector<std::map<int, Token*>> vecContinousPointerTok;
        std::vector<std::string> vecCPOriginal;
        getContinousPointer(scope, vecContinousPointer, vecCPOriginal, vecContinousPointerTok);
        for (const Token* tok = scope->bodyStart; tok && tok != endToken; tok = tok->next()) {
            if (isSkip(tok)) {
                continue;
            }

            if (!isCheckNull(scope, tok)) {
                report_error_info(tok);
            } 
        }

        checkContinousNull(scope, vecContinousPointer, vecCPOriginal, vecContinousPointerTok);
    }
}

/**
 * E.g.:
 *     1. a->b->c
 *     2. a->b()->c()->d
 */
void CheckPointerBeforeUse::getContinousPointer(const Scope* scope, 
        std::vector<std::string> &continuous_pointer,
        std::vector<std::string> &continuous_pointer_original,
        std::vector<std::map<int, Token*>> &continuous_pointer_token) {

    for (const Token* tok = scope->bodyStart; tok && tok != scope->bodyEnd; tok = tok->next()) {
        if (isSkip(tok)) {
            continue;
        }

        // scane from the token to the parent token in the ast.
        // If find ->, then the token before -> should check NULL.
        std::string continousPointerString = "";
        std::string cpOriginal = "";

        const Token* astParentTok = tok->astParent();

        while (astParentTok) {
            //tok = astParentTok;

            if (astParentTok->originalName() == "->") {
                if (!continousPointerString.empty()) { // for the a->b->c, skip the a->b check.
                    //continuous_pointer.insert(std::pair<std::string, int>(continousPointerString, astParentTok->linenr()));
                    continuous_pointer.push_back(continousPointerString);
                    continuous_pointer_original.push_back(cpOriginal);

                    std::map<int, Token*> mt;
                    mt[0] = const_cast<Token*>(tok);
                    mt[1] = astParentTok->previous();
                    continuous_pointer_token.push_back(mt);
                }
            }

            if (astParentTok->str() == "(") {
                continousPointerString += (" " + getTokenString(astParentTok, astParentTok->link()));
                cpOriginal += getTokenString(astParentTok, astParentTok->link());
                //tok = astParentTok->link();
                //std::cout << "---" << getTokenString(astParentTok, astParentTok->link()) << std::endl;
            } else if (astParentTok->str() == "."){
                // 中序遍历
                if (continousPointerString == "") {
                    continousPointerString += astParentTok->astOperand1()->str();
                    cpOriginal += astParentTok->astOperand1()->str();
                }
                if (!astParentTok->originalName().empty()) {
                    continousPointerString += (" " + astParentTok->str());
                    cpOriginal += astParentTok->originalName();
                } else {
                    continousPointerString += (" " + astParentTok->str());
                    cpOriginal += astParentTok->str();
                }
                
                continousPointerString += (" " + astParentTok->astOperand2()->str());
                cpOriginal += astParentTok->astOperand2()->str();
            }

            astParentTok = astParentTok->astParent();
        }
    }
}

std::string CheckPointerBeforeUse::getTokenString(const Token* begin, const Token* end) const {
    std::string tokString = "";
    if (!begin || !end) {
        return tokString;
    }

    for (const Token* tok = begin; tok && tok != end; tok=tok->next()) {
        tokString += (tokString == "" ? tok->str() : " " + tok->str());
    }
    tokString += (" " + end->str());

    return tokString;
}

bool CheckPointerBeforeUse::isSkip(const Token* tok) {
    bool unknown = false;

    // S1. 过滤非解引用的变量
    if (!isPointerDeRef(tok, unknown)) {
        return true;   
    }

    // S2. 过滤非变量，非局部变量，非指针变量
    if (!tok->variable() || !(tok->variable()->isLocal()) || !(tok->variable()->isPointer())) {
        return true;
    }

    // S3. 过滤容器类型
    if (isContainerType(tok)) {
        return true;
    }

    return false;
}

bool CheckPointerBeforeUse::isContainerType(const Token* tok) {
    bool isContainerType = false;
    if (!(tok && tok->variable())) {
        return isContainerType;
    }

    for (const Token *tokType = tok->variable()->typeStartToken();
         tokType && tokType != tok->variable()->typeEndToken();
         tokType = tokType->next()) {

        auto res = std::find(mFilterContainerType.begin(), mFilterContainerType.end(), tokType->str());
        if (res != mFilterContainerType.end()){
            isContainerType = true;
            break;
        }
    }

    return isContainerType;
}

bool CheckPointerBeforeUse::isCheckNull(const Scope *scope, const Token *tok) {
    const Token *tok1 = tok;
    for (; tok1 && tok1 != scope->bodyStart; tok1 = tok1->previous()) {
        if (tok1->str() == tok->str() && tok1->astParent()) {
            if (tok1->astParent()->str() == "!") {
                return true;
            }

            if ((tok1->astParent()->str() == "!=" || tok1->astParent()->str() == "==") && 
                (tok1->astParent()->astOperand2()->str() == "NULL" || 
                 tok1->astParent()->astOperand2()->str() == "nullptr" || 
                 tok1->astParent()->astOperand1()->str() == "NULL" ||
                 tok1->astParent()->astOperand1()->str() == "nullptr")) {
                return true;
            }
        }
            
    }

    return false;
}

void CheckPointerBeforeUse::checkContinousNull(const Scope *scope, 
        std::vector<std::string> &continuous_pointer,
        std::vector<std::string> &continuous_pointer_original,
        std::vector<std::map<int, Token*>> &continuous_pointer_token) {
        int i = 0;
        for (auto item : continuous_pointer) {
            const Token *tok = scope->bodyStart;
            bool isCheck = false;
            std::map<int, Token*> m = continuous_pointer_token[i];

            for (; tok && tok != m[1]; tok = tok->next()) {
                if (Token::Match(tok, ("! " + item).c_str()) || 
                    Token::Match(tok, ("NULL == " + item).c_str()) ||
                    Token::Match(tok, (item + " == NULL").c_str()) ||
                    Token::Match(tok, ("nullptr == " + item).c_str()) ||
                    Token::Match(tok, (item + " == nullptr").c_str()) ||
                    Token::Match(tok, ("NULL != " + item).c_str()) ||
                    Token::Match(tok, (item + " != NULL").c_str()) ||
                    Token::Match(tok, ("nullptr != " + item).c_str()) ||
                    Token::Match(tok, (item + " != nullptr").c_str())) {
                    isCheck = true;
                    break;
                }
            }

            if (!isCheck) {
                reportError(
                    m[0],
                    Severity::error,
                    "not check pointer before use",
                    continuous_pointer_original[i] + " may cause segment fault",
                    CWE398,
                    false);
            }
            i++;    
        }
}

/** the format of the configure: 
 */
void CheckPointerBeforeUse::loadConf(const YAML::Node &configure) {
    if (!configure["CheckPointerBeforeUse"]) {
        return;
    }

    for (const auto& it_ct: configure["CheckPointerBeforeUse"]["containerType"]) {
        mFilterContainerType.push_back(it_ct.as<std::string>());
        //std::cout << it_ct.as<std::string>() << std::endl;
    }
}

/**
 * Is there a pointer dereference? Everything that should result in
 * a nullpointer dereference error message will result in a true
 * return value. If it's unknown if the pointer is dereferenced false
 * is returned.
 * @param tok token for the pointer
 * @param unknown it is not known if there is a pointer dereference (could be reported as a debug message)
 * @return true => there is a dereference
 */
bool CheckPointerBeforeUse::isPointerDeRef(const Token *tok, bool &unknown)
{
    unknown = false;

    const Token* parent = tok->astParent();
    if (!parent)
        return false;
    if (parent->str() == "." && parent->astOperand2() == tok)
        return isPointerDeRef(parent, unknown);
    const bool firstOperand = parent->astOperand1() == tok;
    while (parent->str() == "(" && (parent->astOperand2() == nullptr && parent->strAt(1) != ")")) { // Skip over casts
        parent = parent->astParent();
        if (!parent)
            return false;
    }

    // Dereferencing pointer..
    if (parent->isUnaryOp("*") && !Token::Match(parent->tokAt(-2), "sizeof|decltype|typeof"))
        return true;

    // array access
    if (firstOperand && parent->str() == "[" && (!parent->astParent() || parent->astParent()->str() != "&")) {
        // skip the array declare.
        if (tok->variable() && tok->variable()->typeStartToken()->linenr() == tok->linenr()) {
            return false;
        }
        return true;
    }

    // address of member variable / array element
    const Token *parent2 = parent;
    while (Token::Match(parent2, "[|."))
        parent2 = parent2->astParent();
    if (parent2 != parent && parent2 && parent2->isUnaryOp("&"))
        return false;

    // read/write member variable, or access the member function.
    if (firstOperand && parent->str() == "." && (!parent->astParent() || parent->astParent()->str() != "&")) {
        //a->b();
        if (parent->astParent() && parent->astParent()->str() == "(") {
            return true;
        }

        if (!parent->astParent() || parent->astParent()->str() != "(" || parent->astParent() == tok->previous()) {
            return true;
        }
        
        unknown = true;
        return false;
    }

    if (Token::Match(tok, "%name% ("))
        return true;

    if (Token::Match(tok, "%var% = %var% .") &&
        tok->varId() == tok->tokAt(2)->varId())
        return true;

    // std::string dereferences nullpointers
    if (Token::Match(parent->tokAt(-3), "std :: string|wstring (") && tok->strAt(1) == ")")
        return true;
    if (Token::Match(parent->previous(), "%name% (") && tok->strAt(1) == ")") {
        const Variable* var = tok->tokAt(-2)->variable();
        if (var && !var->isPointer() && !var->isArray() && var->isStlStringType())
            return true;
    }

    // streams dereference nullpointers
    if (Token::Match(parent, "<<|>>") && !firstOperand) {
        const Variable* var = tok->variable();
        if (var && var->isPointer() && Token::Match(var->typeStartToken(), "char|wchar_t")) { // Only outputting or reading to char* can cause problems
            const Token* tok2 = parent; // Find start of statement
            for (; tok2; tok2 = tok2->previous()) {
                if (Token::Match(tok2->previous(), ";|{|}|:"))
                    break;
            }
            if (Token::Match(tok2, "std :: cout|cin|cerr"))
                return true;
            if (tok2 && tok2->varId() != 0) {
                const Variable* var2 = tok2->variable();
                if (var2 && var2->isStlType(stl_stream))
                    return true;
            }
        }
    }

    const Variable *ovar = nullptr;
    if (Token::Match(parent, "+|==|!=") || (parent->str() == "=" && !firstOperand)) {
        if (parent->astOperand1() == tok && parent->astOperand2())
            ovar = parent->astOperand2()->variable();
        else if (parent->astOperand1() && parent->astOperand2() == tok)
            ovar = parent->astOperand1()->variable();
    }
    if (ovar && !ovar->isPointer() && !ovar->isArray() && ovar->isStlStringType())
        return true;

    // assume that it's not a dereference (no false positives)
    return false;
}

void CheckPointerBeforeUse::report_error_info(const Token* tok) {
    reportError(
            tok,
            Severity::error,
            "not check pointer before use",
            tok->str() + " may cause segment fault",
            CWE398,
            false
    );
}

void CheckPointerBeforeUse::report_warning_info(const Token* tok) {
    reportError(
            tok,
            Severity::warning,
            "not check pointer before use",
            "may cause segment fault",
            CWE398,
            false
    );
}