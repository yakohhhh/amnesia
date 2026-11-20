# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Inventaire statique de scripts PowerShell, lu sur leur AST sans rien executer.

.DESCRIPTION
Pour chaque script recu en argument, rend en JSON ses erreurs d'analyse et la
liste de ses commandes (CommandAst) avec le nom de leurs parametres, leurs
arguments constants et le devenir de leur sortie, de ses appels de methodes
.NET (InvokeMemberExpressionAst), des proprietes qu'il lit
(MemberExpressionAst), des types qu'il nomme (conversions, contraintes,
attributs, operateur -as), de ses affectations, de ses redirections vers un
fichier et de ses instructions using. Ce script ne decide rien : le verdict
revient a amnesia.readonly.check_script_inventory (garantie de lecture seule,
#39) et a amnesia.privacy.check_script_privacy (minimisation, #41), appeles
par tests/integration/test_scripts_powershell.py.

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

function Get-Commande {
    param($Noeud)

    # nom des parametres (-ComputerName joint un autre hote) ; des parametres
    # etales (@variable) sont hors de vue de l'analyse. Constantes texte passees
    # en argument (nom nu ou chaine, tableau a, b, c compris) : une propriete
    # peut y etre nommee (Select-Object Message). dynamic : un argument au
    # moins n'est pas une constante
    $parametres = [System.Collections.Generic.List[string]]::new()
    $constantes = [System.Collections.Generic.List[string]]::new()
    $etale = $false
    $dynamique = $false
    $aVoir = [System.Collections.Generic.Queue[object]]::new()
    $premier = $true
    foreach ($argument in $Noeud.CommandElements) {
        if ($premier) {
            # le nom de la commande
            $premier = $false
            continue
        }
        if ($argument -is [System.Management.Automation.Language.CommandParameterAst]) {
            $parametres.Add($argument.ParameterName)
            # forme -Nom:valeur
            if ($null -ne $argument.Argument) {
                $aVoir.Enqueue($argument.Argument)
            }
        }
        else {
            $aVoir.Enqueue($argument)
        }
        while ($aVoir.Count -gt 0) {
            $expression = $aVoir.Dequeue()
            if ($expression -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $constantes.Add($expression.Value)
            }
            elseif ($expression -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                foreach ($membre in $expression.Elements) {
                    $aVoir.Enqueue($membre)
                }
            }
            elseif ($expression -is [System.Management.Automation.Language.ConstantExpressionAst]) {
                # nombre : ni nom de propriete, ni valeur calculee
                continue
            }
            else {
                $dynamique = $true
                if ($expression -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    if ($expression.Splatted) {
                        $etale = $true
                    }
                }
            }
        }
    }
    # GetCommandName() rend $null pour un nom calcule a l'execution
    return [ordered]@{
        kind       = 'command'
        name       = $Noeud.GetCommandName()
        parameters = $parametres
        splat      = $etale
        arguments  = $constantes
        dynamic    = $dynamique
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
            $element = Get-Commande -Noeud $noeud
            # devenir de la sortie (minimisation, #41) : 'member' si une seule
            # propriete en est lue, (commande).Propriete ; 'pipeline' si elle
            # passe a une autre commande, decrite dans next ; 'none' sinon
            # (emise telle quelle, rangee dans une variable, passee en argument)
            $projection = 'none'
            $membre = $null
            $suivant = $null
            $pipeline = $noeud.Parent
            if ($pipeline -is [System.Management.Automation.Language.PipelineAst]) {
                $rang = $pipeline.PipelineElements.IndexOf($noeud)
                if ($rang -lt ($pipeline.PipelineElements.Count - 1)) {
                    $projection = 'pipeline'
                    $voisin = $pipeline.PipelineElements[$rang + 1]
                    if ($voisin -is [System.Management.Automation.Language.CommandAst]) {
                        $suivant = Get-Commande -Noeud $voisin
                    }
                }
                elseif ($pipeline.Parent -is [System.Management.Automation.Language.ParenExpressionAst]) {
                    $parenthese = $pipeline.Parent
                    $acces = $parenthese.Parent
                    if (($acces -is [System.Management.Automation.Language.MemberExpressionAst]) -and ($acces -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst])) {
                        if ([object]::ReferenceEquals($acces.Expression, $parenthese)) {
                            $projection = 'member'
                            if ($acces.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                                $membre = $acces.Member.Value
                            }
                        }
                    }
                }
            }
            $element['projection'] = $projection
            $element['member'] = $membre
            $element['next'] = $suivant
            $element['line'] = $ligne
            $elements.Add($element)
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
        elseif ($noeud -is [System.Management.Automation.Language.MemberExpressionAst]) {
            # lecture d'une propriete ($evenement.Message) : InvokeMemberExpressionAst,
            # qui en derive, est traite plus haut. $null : nom calcule a l'execution
            $nom = $null
            if ($noeud.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $nom = $noeud.Member.Value
            }
            $elements.Add([ordered]@{
                    kind   = 'property'
                    name   = $nom
                    static = [bool] $noeud.Static
                    line   = $ligne
                })
        }
        elseif (($noeud -is [System.Management.Automation.Language.TypeExpressionAst]) -or ($noeud -is [System.Management.Automation.Language.AttributeBaseAst])) {
            # une conversion ([Type]$valeur, [Type]@{...}, -as [Type]) appelle un
            # constructeur ou des accesseurs : le type compte autant qu'une
            # methode. AttributeBaseAst couvre contraintes de type et attributs
            $elements.Add([ordered]@{
                    kind = 'type'
                    name = $noeud.TypeName.FullName
                    line = $ligne
                })
        }
        elseif ($noeud -is [System.Management.Automation.Language.BinaryExpressionAst]) {
            # -as 'Nom.De.Type' : type nomme par une chaine ou calcule
            if (($noeud.Operator.ToString() -eq 'As') -and ($noeud.Right -isnot [System.Management.Automation.Language.TypeExpressionAst])) {
                $elements.Add([ordered]@{
                        kind = 'type'
                        name = $null
                        line = $ligne
                    })
            }
        }
        elseif ($noeud -is [System.Management.Automation.Language.ForEachStatementAst]) {
            # la variable d'iteration est affectee a chaque tour
            $elements.Add((Get-Affectation -Cible $noeud.Variable -Ligne $ligne))
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
ConvertTo-Json -InputObject $inventaires -Depth 8 -Compress
