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
        bool unknown = false;

        for (const Token* tok = scope->bodyStart; tok && tok != endToken; tok = tok->next()) {
            //std::cout << tok->str() << ", " << tok->tokType() << std::endl;
            //If the variable deferenced, then check.
            if (!isPointerDeRef(tok, unknown)) {
                continue;    
            }

            //If check the variable before deference.
            // Just check the local pointer variable.
            if (!tok->variable() || !(tok->variable()->isLocal()) || !(tok->variable()->isPointer())) {
                continue;
            }

            // skip the std::container variable, but not the smart pointer.
            bool isContainerType = false;
            for (const Token *tokType = tok->variable()->typeStartToken();
                 tokType && tokType != tok->variable()->typeEndToken();
                 tokType = tokType->next()) {

                auto res = std::find(mFilterContainerType.begin(), mFilterContainerType.end(), tokType->str());
                if (res != mFilterContainerType.end()){
                    isContainerType = true;
                    break;
                }
            }
            if (isContainerType) {
                continue;
            }

            if (!isCheckNull(scope, tok)) {
                report_error_info(tok);
                //std::cout << "the unknow value is: " << unknown << std::endl; 
            } 
        }
    }
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