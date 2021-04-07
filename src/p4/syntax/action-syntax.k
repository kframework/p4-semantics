require "header-syntax.k"

module ACTION

endmodule

module ACTION-SYNTAX
imports HEADER-SYNTAX //only for header reference
    syntax ActionName ::= Id
    syntax ParamName ::= Id


// 9.2 ActionDefinitions
    syntax ActionFunctionDeclaration ::=
        "action" ActionHeader "{"
            ActionStatements
        "}"
    //P4 assumes parallel semantics for the application of all the primitive actions executing as a result of a match in a given table. The execution of actions across different tables assumes sequential semantics where the sequence is determined by the control flow,
    //TODO ISSUE parallel at which level of granularity?

    syntax ActionStatements ::= List{ActionStatement,""}    [klabel('ActionStatements)]

    syntax ActionHeader ::= ActionName "(" ParamList ")"

    syntax ParamList ::= List{ParamName,","}                [klabel('ParamList)]

    syntax ActionStatement ::=
                  ActionName "(" Args ")" ";"


    syntax Args ::= List{Arg, ","}                          [klabel('Args)]

    syntax Arg ::=
        //  ParamName         [klabel('ArgParamName)] //TODO ISSUE(SYNTAX): causes ambiguity with HeaderRef
          FieldValue        //[klabel('ArgFieldValue)]
        | FieldRef          //[klabel('ArgFieldRef)]
        | HeaderRef         //[klabel('ArgHeaderRef)]

endmodule

module ACTION-PROFILE-SYNTAX
imports ACTION-SYNTAX // for ActionName + ConstValue
imports CHECKSUM-SYNTAX // for FieldListCalculationName
    syntax ActionProfileName ::= Id
    syntax SelectorName ::= Id

// 10 Action profile declarations
    syntax ActionProfileDeclaration ::=
            "action_profile" ActionProfileName "{"
                ActionSpecification
                ActionsProfileOptionals
                //OptionalSize
                //OptionalDynamicActionSelection

            "}"

    //TODO Note: current workraround for problem with None. note that this is not the official syntax, but it can be turned into semantic check insteaf of syntactic check
    syntax ActionsProfileOptionals ::= List{ActionsProfileOptional,""} [klabel('ActionsProfileOptionals)]
    syntax ActionsProfileOptional ::=
              "size" ":" ConstValue ";"
            | "dynamic_action_selection" ":" SelectorName ";"

    //syntax OptionalSize ::= None | "size" ":" ConstValue ";"
    //syntax OptionalDynamicActionSelection ::= "dynamic_action_selection" ":" SelectorName ";"

    syntax ActionSpecification ::= "actions" "{" ActionNameItems "}"
    syntax ActionNameItems ::= NeList{ActionNameItem,""}                [klabel('ActionNameItems)]
    syntax ActionNameItem ::= ActionName ";"    [klabel('ActionNameItem)]

    syntax ActionSelectorDeclaration ::=
            "action_selector" SelectorName "{"
                "selection_key" ":" FieldListCalculationName ";"
            "}"
endmodule