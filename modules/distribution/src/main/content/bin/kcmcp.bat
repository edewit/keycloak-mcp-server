@echo off
rem Starts keycloak-mcp-server from this distribution.
rem
rem   bin\kcmcp.bat start                                     conf\kcmcp.properties
rem   bin\kcmcp.bat start --config conf\scenarios\read-only.properties
rem   bin\kcmcp.bat start --kc-mcp.url=https://sso.example.com --quarkus.http.port=8082
rem   bin\kcmcp.bat start --debug 5005
rem   bin\kcmcp.bat --version | --help
rem
rem Any --name=value becomes the configuration property "name"; environment variables (KC_MCP_URL=...) work as well.
rem JAVA_HOME or JAVA pick the JVM (Java 21 or newer); JAVA_OPTS replaces the default JVM options, JAVA_OPTS_APPEND
rem adds to them. KCMCP_DEBUG=true, KCMCP_DEBUG_PORT and KCMCP_DEBUG_SUSPEND enable remote debugging.

setlocal enabledelayedexpansion

set "BIN_DIR=%~dp0"
pushd "%BIN_DIR%.."
set "KCMCP_HOME=%CD%"
popd

set DEBUG_MODE=false
set DEBUG_ADDRESS=5005
set DEBUG_SUSPEND_VAR=n
if not "%KCMCP_DEBUG%" == "" set DEBUG_MODE=%KCMCP_DEBUG%
if not "%KCMCP_DEBUG_PORT%" == "" set DEBUG_ADDRESS=%KCMCP_DEBUG_PORT%
if not "%KCMCP_DEBUG_SUSPEND%" == "" set DEBUG_SUSPEND_VAR=%KCMCP_DEBUG_SUSPEND%

rem configuration files go to quarkus.config.locations as file:/// URIs with forward slashes: a bare drive letter
rem would be read as a URI scheme
set "HOME_URI=%KCMCP_HOME:\=/%"
set "CONFIG_FILES=file:///%HOME_URI%/conf/kcmcp.properties"
set SERVER_OPTS=
set COMMAND=

rem cmd splits "--name=value" and "-Dname=value" at the "=": KEY is the part before it, VALUE the part after
:READ_ARGS
set "KEY=%~1"
if "%KEY%" == "" goto MAIN
if "%KEY%" == "start" (
    set COMMAND=start
    shift
    goto READ_ARGS
)
if "%KEY%" == "--help" goto USAGE
if "%KEY%" == "-h" goto USAGE
if "%KEY%" == "--version" goto VERSION
if "%KEY%" == "-v" goto VERSION
if "%KEY%" == "--debug" (
    set DEBUG_MODE=true
    set "NEXT=%~2"
    if not "!NEXT!" == "" (
        echo !NEXT!| findstr /R "^[0-9][0-9]*$" >nul && (
            set DEBUG_ADDRESS=!NEXT!
            shift
        )
    )
    shift
    goto READ_ARGS
)
if "%KEY%" == "--config" (
    rem absolute, relative to the current directory, or relative to the distribution
    set "CFG=%~f2"
    if not exist "!CFG!" if exist "%KCMCP_HOME%\%~2" set "CFG=%KCMCP_HOME%\%~2"
    if not exist "!CFG!" (
        echo configuration file not found: %~2 1>&2
        exit /b 2
    )
    set "CONFIG_FILES=!CONFIG_FILES!,file:///!CFG:\=/!"
    shift
    shift
    goto READ_ARGS
)
if "%KEY:~0,2%" == "-D" (
    set "VALUE=%~2"
    if not "!VALUE!" == "" if not "!VALUE:~0,1!" == "-" (
        set "SERVER_OPTS=!SERVER_OPTS! "%KEY%=!VALUE!""
        shift
        shift
        goto READ_ARGS
    )
    set "SERVER_OPTS=!SERVER_OPTS! "%KEY%""
    shift
    goto READ_ARGS
)
if "%KEY:~0,2%" == "--" (
    set "NAME=%KEY:~2%"
    set "VALUE=%~2"
    if "!VALUE!" == "" (
        echo --!NAME! needs a value, as --!NAME!=value 1>&2
        exit /b 2
    )
    set "SERVER_OPTS=!SERVER_OPTS! "-D!NAME!=!VALUE!""
    shift
    shift
    goto READ_ARGS
)
echo unknown argument: %KEY% (try --help^) 1>&2
exit /b 2

:USAGE
for /f "usebackq skip=1 tokens=* delims=" %%L in ("%~f0") do (
    set "LINE=%%L"
    if "!LINE:~0,3!" == "rem" (
        echo !LINE:~4!
    ) else (
        goto :EOF
    )
)
goto :EOF

:VERSION
if exist "%KCMCP_HOME%\version.txt" (type "%KCMCP_HOME%\version.txt") else (echo unknown)
goto :EOF

:MAIN
if "%COMMAND%" == "" goto USAGE

if "%JAVA%" == "" (
    if not "%JAVA_HOME%" == "" (
        set "JAVA=%JAVA_HOME%\bin\java"
    ) else (
        set "JAVA=java"
    )
)

if "%JAVA_OPTS%" == "" (
    set "JAVA_OPTS=-Xms64m -Xmx512m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError -Dfile.encoding=UTF-8"
)
if not "%JAVA_OPTS_APPEND%" == "" set "JAVA_OPTS=%JAVA_OPTS% %JAVA_OPTS_APPEND%"
if "%DEBUG_MODE%" == "true" (
    set "JAVA_OPTS=%JAVA_OPTS% -agentlib:jdwp=transport=dt_socket,address=%DEBUG_ADDRESS%,server=y,suspend=%DEBUG_SUSPEND_VAR%"
)

rem where this distribution keeps things; the configuration may refer to ${kcmcp.home.dir}
set "HOME_OPTS=-Dkcmcp.home.dir="%KCMCP_HOME%" -Dquarkus.config.locations="%CONFIG_FILES%""
set "HOME_OPTS=%HOME_OPTS% -Dkc-mcp.providers-dir="%KCMCP_HOME%\providers" -Dkc-mcp.keys-dir="%KCMCP_HOME%\data\keys""
set "HOME_OPTS=%HOME_OPTS% -Djava.util.logging.manager=org.jboss.logmanager.LogManager"

if "%KCMCP_PRINT_ENV%" == "true" (
    echo Using JAVA: %JAVA%
    echo Using JAVA_OPTS: %JAVA_OPTS%
    echo Using SERVER_OPTS: %HOME_OPTS% %SERVER_OPTS%
)

cd /d "%KCMCP_HOME%"
"%JAVA%" %JAVA_OPTS% %HOME_OPTS% %SERVER_OPTS% -jar "%KCMCP_HOME%\lib\quarkus-run.jar"
exit /b %ERRORLEVEL%
