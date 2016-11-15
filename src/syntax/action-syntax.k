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
          ParamName         [klabel('ArgParamName)]
        | FieldValue        [klabel('ArgFieldValue)]
        | FieldRef          [klabel('ArgFieldRef)]
        | HeaderRef         [klabel('ArgHeaderRef)]

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
                OptionalSize
                OptionalDynamicActionSelection
            "}"


    syntax OptionalSize ::= None | "size" ":" ConstValue ";"
    syntax OptionalDynamicActionSelection ::= "dynamic_action_selection" ":" SelectorName ";"

    syntax ActionSpecification ::= "actions" "{" ActionNameItems "}"
    syntax ActionNameItems ::= NeList{ActionNameItem,""}                [klabel('ActionNameItems)]
    syntax ActionNameItem ::= ActionName ";"

    syntax ActionSelectorDeclaration ::=
            "action_selector" SelectorName "{"
                "selection_key" ":" FieldListCalculationName ";"
            "}"
endmodule