require "header.k"

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

    syntax ActionStatements ::= List{ActionStatement,""}

    syntax ActionHeader ::= ActionName "(" ParamList ")"

    syntax ParamList ::= List{ParamName,","}

    syntax ActionStatement ::=
                  ActionName "(" Args ")" ";"


    syntax Args ::= List{Arg, ","}

    syntax Arg ::= ParamName | FieldValue | FieldRef | HeaderRef

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

    syntax ActionSpecification ::= "actions" "{" ActionNames "}"
    syntax ActionNames ::= NeList{ActionName," "}


    syntax ActionSelectorDeclaration ::=
            "action_selector" SelectorName "{"
                "selection_key" ":" FieldListCalculationName ";"
            "}"
endmodule