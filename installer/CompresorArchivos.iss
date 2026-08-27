#define AppName "NDAC Compresor de Archivos"
#define AppVersion "2.0.0"
#define AppPublisher "Mako9162"
#define AppExeName "CompresorArchivos.exe"

[Setup]
AppId={{D52F011B-5479-4D59-BF73-71F74194AFB1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\NDAC
DefaultGroupName={#AppName}
OutputDir=output
OutputBaseFilename=NDAC-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExeName}
ChangesAssociations=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; GroupDescription: "Accesos directos:"; Flags: unchecked
Name: "assocndac"; Description: "Asociar archivos de extension .ndac con NDAC"; GroupDescription: "Integracion con Windows:"; Flags: checked
Name: "contextmenu"; Description: "Agregar opciones al menu contextual del Explorador de Windows"; GroupDescription: "Integracion con Windows:"; Flags: checked

[Files]
Source: "..\dist\CompresorArchivos.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Asociacion de extension .ndac
Root: HKCR; Subkey: ".ndac"; ValueType: string; ValueValue: "NDAC.Archive"; Tasks: assocndac; Flags: uninsdeletevalue
Root: HKCR; Subkey: "NDAC.Archive"; ValueType: string; ValueValue: "Archivo comprimido NDAC"; Tasks: assocndac; Flags: uninsdeletekey
Root: HKCR; Subkey: "NDAC.Archive\DefaultIcon"; ValueType: string; ValueValue: "{app}\{#AppExeName},0"; Tasks: assocndac
Root: HKCR; Subkey: "NDAC.Archive\shell\open\command"; ValueType: string; ValueValue: """{app}\{#AppExeName}"" ""%1"""; Tasks: assocndac

; Menú contextual para Archivos: Comprimir con NDAC
Root: HKCR; Subkey: "*\shell\NDAC.Compress"; ValueType: string; ValueValue: "Comprimir con NDAC"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\NDAC.Compress\Icon"; ValueType: string; ValueValue: "{app}\{#AppExeName}"; Tasks: contextmenu
Root: HKCR; Subkey: "*\shell\NDAC.Compress\command"; ValueType: string; ValueValue: """{app}\{#AppExeName}"" ""compress"" ""%1"""; Tasks: contextmenu

; Menú contextual para Carpetas: Comprimir carpeta con NDAC
Root: HKCR; Subkey: "Directory\shell\NDAC.CompressFolder"; ValueType: string; ValueValue: "Comprimir carpeta con NDAC"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\NDAC.CompressFolder\Icon"; ValueType: string; ValueValue: "{app}\{#AppExeName}"; Tasks: contextmenu
Root: HKCR; Subkey: "Directory\shell\NDAC.CompressFolder\command"; ValueType: string; ValueValue: """{app}\{#AppExeName}"" ""compress"" ""%1"""; Tasks: contextmenu

; Menú contextual para Archivos .ndac: Extraer con NDAC
Root: HKCR; Subkey: "NDAC.Archive\shell\NDAC.Extract"; ValueType: string; ValueValue: "Extraer con NDAC"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCR; Subkey: "NDAC.Archive\shell\NDAC.Extract\Icon"; ValueType: string; ValueValue: "{app}\{#AppExeName}"; Tasks: contextmenu
Root: HKCR; Subkey: "NDAC.Archive\shell\NDAC.Extract\command"; ValueType: string; ValueValue: """{app}\{#AppExeName}"" ""extract"" ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Abrir {#AppName}"; Flags: nowait postinstall skipifsilent
