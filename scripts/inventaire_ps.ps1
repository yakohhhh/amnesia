# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Inventaire statique de scripts PowerShell, lu sur leur AST sans rien executer.

.DESCRIPTION
Pour chaque script recu en argument, rend en JSON ses erreurs d'analyse et la
liste de ses commandes (CommandAst), de ses appels de methodes .NET
(InvokeMemberExpressionAst), de ses affectations, de ses redirections vers un
fichier et de ses instructions using. Ce script ne decide rien : le verdict
revient a amnesia.readonly.check_script_inventory, appele par
tests/integration/test_scripts_powershell.py (garantie de lecture seule, #39).

    pwsh -NoProfile -NonInteractive -File scripts/inventaire_ps.ps1 <script>...

Outil de developpement et de CI : il n'est jamais execute sur une cible.
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Path = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Affectation {
    param($Cible, [int] $Ligne)

    # seule une variable simple est une cible admise : une variable qualifiee
    # par un lecteur (${C:\fichier}, $env:NOM) ecrit par un fournisseur
    $lecteur = $false
    if ($Cible -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $lecteur = [bool] $Cible.VariablePath.IsDriveQualified
    }
    return [ordered]@{
        kind   = 'assignment'
        target = $Cible.GetType().Name
        drive  = $lecteur
        line   = $Ligne
    }
}

function Get-Inventaire {
    param([string] $Chemin)

    $jetons = $null
    $erreurs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Chemin, [ref] $jetons, [ref] $erreurs)
    $elements = [System.Collections.Generic.List[object]]::new()
    foreach ($noeud in $ast.FindAll({ $true }, $true)) {
        $ligne = $noeud.Extent.StartLineNumber
        if ($noeud -is [System.Management.Automation.Language.CommandAst]) {
            # GetCommandName() rend $null pour un nom calcule a l'execution
            $elements.Add([ordered]@{
                    kind = 'command'
                    name = $noeud.GetCommandName()
                    line = $ligne
                })
        }
        elseif ($noeud -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $nom = $null
            if ($noeud.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $nom = $noeud.Member.Value
            }
            $type = $null
            if ($noeud.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
                $type = $noeud.Expression.TypeName.FullName
            }
            $elements.Add([ordered]@{
                    kind   = 'method'
                    name   = $nom
                    static = [bool] $noeud.Static
                    type   = $type
                    line   = $ligne
                })
        }
        elseif ($noeud -is [System.Management.Automation.Language.AssignmentStatementAst]) {
            $elements.Add((Get-Affectation -Cible $noeud.Left -Ligne $ligne))
        }
        elseif ($noeud -is [System.Management.Automation.Language.UnaryExpressionAst]) {
            # $objet.Propriete++ ecrit comme une affectation
            if ($noeud.TokenKind.ToString() -match 'PlusPlus|MinusMinus') {
                $elements.Add((Get-Affectation -Cible $noeud.Child -Ligne $ligne))
            }
        }
        elseif ($noeud -is [System.Management.Automation.Language.FileRedirectionAst]) {
            $elements.Add([ordered]@{
                    kind = 'redirection'
                    name = $noeud.Location.Extent.Text
                    line = $ligne
                })
        }
        elseif ($noeud -is [System.Management.Automation.Language.UsingStatementAst]) {
            $elements.Add([ordered]@{
                    kind = 'using'
                    name = $noeud.UsingStatementKind.ToString()
                    line = $ligne
                })
        }
    }
    $messages = [System.Collections.Generic.List[object]]::new()
    foreach ($erreur in $erreurs) {
        $messages.Add($erreur.Message)
    }
    return [ordered]@{
        path   = [System.IO.Path]::GetFileName($Chemin)
        errors = $messages
        items  = $elements
    }
}

$inventaires = [System.Collections.Generic.List[object]]::new()
foreach ($chemin in $Path) {
    $inventaires.Add((Get-Inventaire -Chemin $chemin))
}
ConvertTo-Json -InputObject $inventaires -Depth 6 -Compress
