# Efface un journal par une methode .NET (ATT&CK T1070.001).
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog('Security')
